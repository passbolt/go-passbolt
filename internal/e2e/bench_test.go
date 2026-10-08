//go:build integration

package e2e

// Benchmarks against the live server: single calls, and Scenario ones that
// measure whole flows. They run in-process, so they can be profiled:
//
//	go test -tags integration -run='^$' -bench=Scenario -cpuprofile=cpu.pprof ./internal/e2e
//	go tool pprof -http=:8080 cpu.pprof
//
// Cleanup happens in b.Cleanup so deletes are not measured.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/helper"
)

// BenchmarkCreateResource measures a full create round-trip: metadata/secret
// encryption plus the create API call. Names are made unique per iteration so
// repeated runs don't collide on the server.
func BenchmarkCreateResource(b *testing.B) {
	ctx := context.Background()
	i := 0

	b.ReportAllocs()
	for b.Loop() {
		name := fmt.Sprintf("bench-create-%d", i)
		i++
		_, err := helper.CreateResource(ctx, client, "", name, "username", "https://url.lan", "password123", "benchmark resource")
		if err != nil {
			b.Fatalf("CreateResource: %v", err)
		}
	}
}

// BenchmarkGetResource measures a full fetch + decrypt round-trip. One resource
// is created up front; the loop repeatedly retrieves and decrypts it.
func BenchmarkGetResource(b *testing.B) {
	ctx := context.Background()

	id, err := helper.CreateResource(ctx, client, "", "bench-get", "username", "https://url.lan", "password123", "benchmark resource")
	if err != nil {
		b.Fatalf("CreateResource (setup): %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, _, _, _, _, _, err := helper.GetResource(ctx, client, id); err != nil {
			b.Fatalf("GetResource: %v", err)
		}
	}
}

// BenchmarkScenario_ListDecrypt is the CLI's `list resource` hot path: fetch a folder's
// resources with secrets, then decrypt metadata and secret for each. N is fixed at 25.
func BenchmarkScenario_ListDecrypt(b *testing.B) {
	const n = 25
	ctx := context.Background()

	folderID, err := helper.CreateFolder(ctx, client, "", "bench-list")
	if err != nil {
		b.Fatalf("CreateFolder: %v", err)
	}
	var ids []string
	b.Cleanup(func() {
		for _, id := range ids {
			_ = helper.DeleteResource(ctx, client, id)
		}
		_ = helper.DeleteFolder(ctx, client, folderID)
	})
	for i := range n {
		id, err := helper.CreateResource(ctx, client, folderID, fmt.Sprintf("bench-list-%d", i), "username", "https://url.lan", "password123", "benchmark resource")
		if err != nil {
			b.Fatalf("CreateResource: %v", err)
		}
		ids = append(ids, id)
	}

	rTypes, err := client.GetResourceTypesCached(ctx)
	if err != nil {
		b.Fatalf("GetResourceTypesCached: %v", err)
	}
	byID := make(map[string]api.ResourceType, len(rTypes))
	for _, rt := range rTypes {
		byID[rt.ID] = rt
	}

	b.ReportAllocs()
	for b.Loop() {
		resources, err := client.GetResources(ctx, &api.GetResourcesOptions{
			FilterHasParent: []string{folderID},
			ContainSecret:   true,
		})
		if err != nil {
			b.Fatalf("GetResources: %v", err)
		}
		if len(resources) != n {
			b.Fatalf("listed %d resources, want %d", len(resources), n)
		}
		for _, r := range resources {
			if _, _, _, _, _, _, err := helper.GetResourceFromData(client, r, r.Secrets[0], byID[r.ResourceTypeID]); err != nil {
				b.Fatalf("GetResourceFromData: %v", err)
			}
		}
	}
}

// BenchmarkScenario_FolderShareMove creates a folder with three resources, shares it with a
// second user, then moves the resources into an unshared folder (the root is rejected).
func BenchmarkScenario_FolderShareMove(b *testing.B) {
	ctx := context.Background()

	destID, err := helper.CreateFolder(ctx, client, "", "bench-share-dest")
	if err != nil {
		b.Fatalf("CreateFolder: %v", err)
	}

	// Unique per run: -count re-runs this setup against the same server, and
	// register_user refuses an email it has already seen.
	email := fmt.Sprintf("bench-share-%d@passbolt.com", time.Now().UnixNano())
	recipient, err := pb.CreateUser(ctx, email, "Bench", "Share", "user", email)
	if err != nil {
		b.Fatalf("create second user: %v", err)
	}

	var folderIDs, resourceIDs []string
	b.Cleanup(func() {
		for _, id := range resourceIDs {
			_ = helper.DeleteResource(ctx, client, id)
		}
		for _, id := range folderIDs {
			_ = helper.DeleteFolder(ctx, client, id)
		}
		_ = helper.DeleteFolder(ctx, client, destID)
	})

	b.ReportAllocs()
	for b.Loop() {
		folderID, err := helper.CreateFolder(ctx, client, "", fmt.Sprintf("bench-share-%d", len(folderIDs)))
		if err != nil {
			b.Fatalf("CreateFolder: %v", err)
		}
		folderIDs = append(folderIDs, folderID)

		var ids []string
		for i := range 3 {
			id, err := helper.CreateResource(ctx, client, folderID, fmt.Sprintf("bench-share-%d-%d", len(folderIDs), i), "username", "https://url.lan", "password123", "benchmark resource")
			if err != nil {
				b.Fatalf("CreateResource: %v", err)
			}
			ids = append(ids, id)
		}
		resourceIDs = append(resourceIDs, ids...)

		if err := helper.ShareFolderWithUsersAndGroups(ctx, client, folderID, []string{recipient.UserID}, nil, 7); err != nil {
			b.Fatalf("ShareFolderWithUsersAndGroups: %v", err)
		}
		for _, id := range ids {
			if err := helper.MoveResource(ctx, client, id, destID); err != nil {
				b.Fatalf("MoveResource: %v", err)
			}
		}
	}
}

// BenchmarkScenario_UpdateRoundTrip is the write path after create: re-encrypt
// metadata and secret for every user with access, then PUT.
func BenchmarkScenario_UpdateRoundTrip(b *testing.B) {
	ctx := context.Background()

	id, err := helper.CreateResource(ctx, client, "", "bench-update", "username", "https://url.lan", "password123", "benchmark resource")
	if err != nil {
		b.Fatalf("CreateResource: %v", err)
	}
	b.Cleanup(func() { _ = helper.DeleteResource(ctx, client, id) })

	i := 0
	b.ReportAllocs()
	for b.Loop() {
		i++
		if err := helper.UpdateResource(ctx, client, id, "bench-update", "username", "https://url.lan", fmt.Sprintf("password-%d", i), fmt.Sprintf("update %d", i)); err != nil {
			b.Fatalf("UpdateResource: %v", err)
		}
	}
}
