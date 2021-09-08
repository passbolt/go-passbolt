# go-passbolt
[![Go Reference](https://pkg.go.dev/badge/github.com/speatzle/go-passbolt.svg)](https://pkg.go.dev/github.com/speatzle/go-passbolt)

A Go module to interact with [Passbolt](https://www.passbolt.com/), an open-source password manager for teams

There also is a CLI Tool to interact with Passbolt using this module [here](https://speatzle/go-passbolt-cli).

This module tries to support the latest Passbolt Community/PRO server release, PRO Features such as folders are supported. Older versions of Passbolt such as v2 are unsupported (it's a password manager, please update it)

This module is divided into two packages: API and helper. 

In the API package, you will find everything to directly interact with the API. 

The helper package has simplified functions that use the API package to perform common but complicated tasks such as sharing a password. 

To use the API package, please read the [Passbolt API docs](https://help.passbolt.com/api). Sadly the docs aren't complete so many things here have been found by looking at the source of Passbolt or through trial and error. If you have a question just ask.

PR's are welcome. But be gentle: if it's something bigger or fundamental: please [create an issue](https://github.com/speatzle/go-passbolt/issues/new) and ask first.

# Install

`go get github.com/speatzle/go-passbolt`

# Examples
## Login

First, you will need to create a client and then log in on the server using the client:

```go
package main

import (
	"context"
	"fmt"

	"github.com/speatzle/go-passbolt/api"
)

const address = "https://passbolt.example.com"
const userPassword = "aStrongPassword"
const userPrivateKey = `
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.6.2
Comment: https://openpgpjs.org
klasd...
-----END PGP PRIVATE KEY BLOCK-----`

func main() {
	client, err := api.NewClient(nil, "", address, userPrivateKey, userPassword)
	if err != nil {
		panic(err)
	}

    	ctx := context.TODO()

	err = client.Login(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Logged in!")
}
```

Note: if you want to use the client for a long time then you'll have to make sure it is still logged in.

You can do this using the `client.CheckSession()` function.

## Create a Resource

Creating a resource using the helper package is simple. First, add `"github.com/speatzle/go-passbolt/helper"` to your imports.

Then you can simply:

```go
resourceID, err := helper.CreateResource(
	ctx,                        // Context
	client,                     // API Client
	"",                         // ID of Parent Folder (PRO only)
	"Example Account",          // Name
	"user123",                  // Username
	"https://test.example.com", // URI
	"securePassword123",        // Password
	"This is an Account for the example test portal", // Description
)
```

Creating a (legacy) resource without the helper package would look like this:

```go
enc, err := client.EncryptMessage("securePassword123")
if err != nil {
	panic(err)
}

res := api.Resource{
	Name:           "Example Account",
	Username:       "user123",
	URI:            "https://test.example.com",
	Description:    "This is an Account for the example test portal",
	Secrets: []api.Secret{
		{Data: enc},
	},
}

resource, err := client.CreateResource(ctx, res)
if err != nil {
	panic(err)
}
```

Note: Since Passbolt v3 there are resource types. This manual example creates a "password-string" type password where the description is unencrypted. Read more [here](https://help.passbolt.com/api/resource-types).

## Getting

Generally, API GET calls will have parameters that allow specifying `filters` and `contains`, if you don't want to define those parameters just pass nil.

`Filters` just filter by whatever is given, `contains` on the other hand specify what information you want to include in the response. Many `filters` and `contains` are undocumented in the Passbolt docs.

Here we specify that we want to filter by favorites and that the response should contain the permissions for each resource:

```go
favorites, err := client.GetResources(ctx, &api.GetResourcesOptions{
	FilterIsFavorite: true,
    ContainPermissions: true,
})
```

We can do the same for users:

```go
users, err := client.GetUsers(ctx, &api.GetUsersOptions{
	FilterSearch:        "Samuel",
	ContainLastLoggedIn: true,
})
```

Groups:

```go
groups, err := client.GetGroups(ctx, &api.GetGroupsOptions{
    FilterHasUsers: []string{"id of user", "id of other user"},
	ContainUser: true,
})
```

And also for folders (PRO only):

```go
folders, err := client.GetFolders(ctx, &api.GetFolderOptions{
	FilterSearch:             "Test Folder",
	ContainChildrenResources: true,
})
```

Getting by ID is also supported using the singular form:

```go
resource, err := client.GetResource(ctx, "resource ID")
```

Since the password is encrypted (and sometimes the description too) the helper package has a function to decrypt all encrypted fields automatically:

```go
folderParentID, name, username, uri, password, description, err := helper.GetResource(ctx, client, "resource id")
```

## Updating

The helper package has a function to save you from dealing with resource types when updating a resource:

```go
err = helper.UpdateResource(
	ctx,           // Context
	client,        // API Client
	"id",          // Resource ID
	"name",        // Name
	"username",    // Username
	"url",         // URI
	"strong",      // Password
	"very strong", // Description
)
```

The same goes for Groups:

```go
err = helper.UpdateGroup(
	ctx,    // Context
	client, // API Client
	"id",   // Group ID
	"name", // Group Name
	[]helper.GroupMembershipOperation{
		{
			UserID:         "id",  // ID of User to Add/Modify/Delete
			IsGroupManager: true,  // Should User be a Group Manager
			Delete:         false, // Should this User be Remove from the Group
		},
	}
)
```

And for Users:

```go
err = helper.UpdateUser(
	ctx,         // Context
	client,      // API Client
	"id",        // User ID
	"user",      // Role (user or admin)
	"firstname", // FirstName
	"lastname",  // LastName
)
```
Note: These helpers will only update fields that are not "".

Helper update functions also exists for Folders.

## Sharing

As sharing resources is very complicated there are multiple helper functions. 

During sharing you will encounter the [permission type](https://github.com/passbolt/passbolt_api/blob/858971516c5e61e1f1be37b007693f0869a70486/src/Model/Entity/Permission.php#L43-L45).

The `permissionType` can be:

| Code | Meaning | 
| --- | --- | 
| `1` | "Read-only" | 
| `7` | "Can update" | 
| `15` | "Owner" |
| `-1` | Delete existing permission | 

The `ShareResourceWithUsersAndGroups` function shares the resource with all provided users and groups with the given `permissionType`.

```go
err := helper.ShareResourceWithUsersAndGroups(ctx, client, "resource id", []string{"user 1 id"}, []string{"group 1 id"}, 7)
```

Note: Existing permission of users and groups will be adjusted to be of the provided `permissionType`.

If you need to do something more complicated like setting users/groups to different types then you can use `ShareResource` directly:

```go
changes := []helper.ShareOperation{}

// Make this user Owner
changes = append(changes, ShareOperation{
	Type:  15,
	ARO:   "User",
	AROID: "user 1 id",
})

// Make this user "Can Update"
changes = append(changes, ShareOperation{
	Type:  5,
	ARO:   "User",
	AROID: "user 2 id",
})

// Delete this users current permission
changes = append(changes, ShareOperation{
	Type:  -1,
	ARO:   "User",
	AROID: "user 3 id",
})

// Make this group "Read-only"
changes = append(changes, ShareOperation{
	Type:  1,
	ARO:   "Group",
	AROID: "group 1 id",
})

err := helper.ShareResource(ctx, c, resourceID, changes)
```

Note: These functions are also available for folders (PRO)

## Moving (PRO)

In Passbolt PRO there are folders, during the creation of resources and folders you can specify in which folder you want to create the resource/folder inside. But if you want to change which folder the resource/folder is in then you can't use the `Update` function (it is/was possible to update the parent folder using the `Update` function but that breaks things). Instead, you use the `Move` function.

```go
err := client.MoveResource(ctx, "resource id", "parent folder id")
```

```go
err := client.MoveFolder(ctx, "folder id", "parent folder id")
```

## Setup

You can setup a Account using a Invite Link like this:
```go
// Get the UserID and Token from the Invite Link
userID, token, err := ParseInviteUrl(url)

// Make a Client for Registration
rClient, err := api.NewClient(nil, "", "https://localhost", "", "")

// Complete Account Setup
privkey, err := SetupAccount(ctx, rClient, userID, token, "password123")
```

## Other

These examples are just the main use cases of these Modules, many more API calls are supported. Look at the [reference](https://pkg.go.dev/github.com/speatzle/go-passbolt) for more information.


## Full Example

This example:

1. Creates a resource; 
2. Searches for a user named "Test User";
3. Checks that it's not itself; and,
4. Shares the password with the "Test User" if necessary:

```go
package main

import (
	"context"
	"fmt"

	"github.com/speatzle/go-passbolt/api"
	"github.com/speatzle/go-passbolt/helper"
)

const address = "https://passbolt.example.com"
const userPassword = "aStrongPassword"
const userPrivateKey = `
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.6.2
Comment: https://openpgpjs.org
klasd...
-----END PGP PRIVATE KEY BLOCK-----`

func main() {
	ctx := context.TODO()

	client, err := api.NewClient(nil, "", address, userPrivateKey, userPassword)
	if err != nil {
		panic(err)
	}

	err = client.Login(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Logged in!")

	resourceID, err := helper.CreateResource(
		ctx,                        // Context
		client,                     // API Client
		"",                         // ID of Parent Folder (PRO only)
		"Example Account",          // Name
		"user123",                  // Username
		"https://test.example.com", // URI
		"securePassword123",        // Password
		"This is an Account for the example test portal", // Description
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Created Resource")

	users, err := client.GetUsers(ctx, &api.GetUsersOptions{
		FilterSearch: "Test User",
	})
	if err != nil {
		panic(err)
	}

	if len(users) == 0 {
		panic("Cannot Find Test User")
	}

	if client.GetUserID() == users[0].ID {
		fmt.Println("I am the Test User, No Need to Share Password With myself")
        	client.Logout(ctx)
		return
	}

	helper.ShareResourceWithUsersAndGroups(ctx, client, resourceID, []string{users[0].ID}, []string{}, 7)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Shared Resource With Test User %v\n", users[0].ID)

    	client.Logout(ctx)
}
```
