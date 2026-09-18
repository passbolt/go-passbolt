//go:build integration

package helper

// Scenario benchmarks: whole user-facing flows against the ephemeral Passbolt
// booted in TestMain, as opposed to the single-call round-trips in
// resource_bench_test.go. They run in-process, so a CPU profile shows where
// the time goes:
//
//	go test -tags integration -run='^$' -bench=Scenario -cpuprofile=cpu.pprof ./helper
//	go tool pprof -http=:8080 cpu.pprof
//
// Server state is cleaned up in b.Cleanup rather than inside the loop, so the
// deletes are not measured and nothing calls StopTimer under b.Loop.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/passbolt/go-passbolt/api"
)

// BenchmarkScenario_ListDecrypt is the CLI's `list resource` hot path: fetch a folder's
// resources with secrets, then decrypt metadata and secret for each. N is fixed at 25.
func BenchmarkScenario_ListDecrypt(b *testing.B) {
	const n = 25
	ctx := context.Background()

	folderID, err := CreateFolder(ctx, client, "", "bench-list")
	if err != nil {
		b.Fatalf("CreateFolder: %v", err)
	}
	var ids []string
	b.Cleanup(func() {
		for _, id := range ids {
			_ = DeleteResource(ctx, client, id)
		}
		_ = DeleteFolder(ctx, client, folderID)
	})
	for i := range n {
		id, err := CreateResource(ctx, client, folderID, fmt.Sprintf("bench-list-%d", i), "username", "https://url.lan", "password123", "benchmark resource")
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
			if _, _, _, _, _, _, err := GetResourceFromData(client, r, r.Secrets[0], byID[r.ResourceTypeID]); err != nil {
				b.Fatalf("GetResourceFromData: %v", err)
			}
		}
	}
}

// BenchmarkScenario_FolderShareMove creates a folder with three resources, shares it with a
// second user, then moves the resources into an unshared folder (the root is rejected).
func BenchmarkScenario_FolderShareMove(b *testing.B) {
	ctx := context.Background()

	destID, err := CreateFolder(ctx, client, "", "bench-share-dest")
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
			_ = DeleteResource(ctx, client, id)
		}
		for _, id := range folderIDs {
			_ = DeleteFolder(ctx, client, id)
		}
		_ = DeleteFolder(ctx, client, destID)
	})

	b.ReportAllocs()
	for b.Loop() {
		folderID, err := CreateFolder(ctx, client, "", fmt.Sprintf("bench-share-%d", len(folderIDs)))
		if err != nil {
			b.Fatalf("CreateFolder: %v", err)
		}
		folderIDs = append(folderIDs, folderID)

		var ids []string
		for i := range 3 {
			id, err := CreateResource(ctx, client, folderID, fmt.Sprintf("bench-share-%d-%d", len(folderIDs), i), "username", "https://url.lan", "password123", "benchmark resource")
			if err != nil {
				b.Fatalf("CreateResource: %v", err)
			}
			ids = append(ids, id)
		}
		resourceIDs = append(resourceIDs, ids...)

		if err := ShareFolderWithUsersAndGroups(ctx, client, folderID, []string{recipient.UserID}, nil, 7); err != nil {
			b.Fatalf("ShareFolderWithUsersAndGroups: %v", err)
		}
		for _, id := range ids {
			if err := MoveResource(ctx, client, id, destID); err != nil {
				b.Fatalf("MoveResource: %v", err)
			}
		}
	}
}

// BenchmarkScenario_UpdateRoundTrip is the write path after create: re-encrypt
// metadata and secret for every user with access, then PUT.
func BenchmarkScenario_UpdateRoundTrip(b *testing.B) {
	ctx := context.Background()

	id, err := CreateResource(ctx, client, "", "bench-update", "username", "https://url.lan", "password123", "benchmark resource")
	if err != nil {
		b.Fatalf("CreateResource: %v", err)
	}
	b.Cleanup(func() { _ = DeleteResource(ctx, client, id) })

	i := 0
	b.ReportAllocs()
	for b.Loop() {
		i++
		if err := UpdateResource(ctx, client, id, "bench-update", "username", "https://url.lan", fmt.Sprintf("password-%d", i), fmt.Sprintf("update %d", i)); err != nil {
			b.Fatalf("UpdateResource: %v", err)
		}
	}
}
