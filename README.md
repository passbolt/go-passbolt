# go-passbolt
A Go Module to interact with [Passbolt](https://www.passbolt.com/), a Open source Password Manager for Teams

This Module tries to Support the Latest Passbolt Community/PRO Server Release, PRO Features Such as Folders are Supported.
Older Versions of Passbolt such as v2 are unsupported (it's a Password Manager, please update it)

This Module is split into 2 packages: api and helper, in the api package you will find everything to directly interact with the API. The helper Package has simplified functions that use the api package to perform common but complicated tasks such as Sharing a Password. To use the API Package please read the Passbolt API [Docs](https://help.passbolt.com/api).
Sadly the Docs aren't Complete so many Things here have been found by looking at the source of Passbolt or through trial and error, if you have a Question just ask.

PR's are Welcome, if it's something bigger / fundamental: Please make a Issue and ask first.

# Install

`go get github.com/speatzle/go-passbolt`

# Examples
## Login
First you will need to Create a Client, and then Login on the Server using the Client
```
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/speatzle/go-passbolt/api"
)

const passboltAddress = "https://passbolt.example.com"
const userPassword = "aStrongPassword"
const userPrivateKey = `
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.6.2
Comment: https://openpgpjs.org
klasd...
-----END PGP PRIVATE KEY BLOCK-----`

func main() {
	u, err := url.Parse(passboltAddress)
	if err != nil {
		panic(err)
	}

	client, err := api.NewClient(u, nil, "", userPrivateKey, userPassword)
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

Note: if you want to use the client for some time then you'll have to make sure it is still logged in.
You can do this using the `client.CheckSession()` function.

## Create a Resource
Creating a Resource using the helper package is simple, first add `"github.com/speatzle/go-passbolt/helper"` to your imports.
Then you can simply:
```
resourceID, err := helper.CreateResource(
	ctx,                        // Context
	client,                     // API Client
	"",                         // ID of Parent Folder (PRO only)
	"Example Account",          // Name
	"user123",                  // Username
	"https://test.example.com", // URI
	"securePassword123",        // Password
	"This is a Account for the example test portal", // Description
)
```
Creating a (Legacy) Resource Without the helper package would look like this:
```
enc, err := client.EncryptMessage("securePassword123")
if err != nil {
	panic(err)
}

res := api.Resource{
	Name:           "Example Account",
	Username:       "user123",
	URI:            "https://test.example.com",
	Description:    "This is a Account for the example test portal",
	Secrets: []api.Secret{
		{Data: enc},
	},
}

resource, err := client.CreateResource(ctx, res)
if err != nil {
	panic(err)
}
```
Note: Since Passbolt v3 There are Resource Types, this Manual Example just creates a "password-string" Type Password where the Description is Unencrypted, Read More [Here](https://help.passbolt.com/api/resource-types).

## Getting
Generally API Get Calls will have options (opts) that allow for specifing filters and contains, if you dont want to specify options just pass nil.
Filters just filter by whatever is given, contains on the otherhand specify what to include in the response. Many Filters And Contains are undocumented in the Passbolt Docs.

Here We Specify that we want to Filter by Favorites and that the Response Should Contain the Permissions for each Resource:
```
favorites, err := client.GetResources(ctx, &api.GetResourcesOptions{
	FilterIsFavorite: true,
    ContainPermissions: true,
})
```
We Can do the Same for Users:
```
users, err := client.GetUsers(ctx, &api.GetUsersOptions{
	FilterSearch:        "Samuel",
	ContainLastLoggedIn: true,
})
```

Groups:
```
groups, err := client.GetGroups(ctx, &api.GetGroupsOptions{
    FilterHasUsers: []string{"id of user", "id of other user"},
	ContainUser: true,
})
```

And also for Folders (PRO Only):
```
folders, err := client.GetFolders(ctx, &api.GetFolderOptions{
	FilterSearch:             "Test Folder",
	ContainChildrenResources: true,
})
```

Getting by ID is also Supported Using the Singular Form:
```
resource, err := client.GetResource(ctx, "resource ID")
```

Since the Password is Encrypted (and sometimes the description too) the helper package has a function to decrypt all encrypted fields Automatically:
```
folderParentID, name, username, uri, password, description, err := helper.GetResource(ctx, client, "resource id")
```

## Updating
The Helper Package has a function to save you needing to deal with Resource Types When Updating a Resource:
```
err := helper.UpdateResource(ctx, client,"resource id", "name", "username", "https://test.example.com", "pass123", "very descriptive")
```

Note: As Groups are also Complicated to Update there will be a helper function for them in the future.

For other less Complicated Updates you can Simply use the Client directly:
```
client.UpdateUser(ctx, "user id", api.User{
	Profile: &api.Profile{
		FirstName: "Test",
		LastName:  "User",
	},
})
```

## Sharing
As Sharing Resources is very Complicated there are multipe helper Functions. During Sharing you will encounter the permissionType.

The permissionType can be 1 for Read only, 7 for Can Update, 15 for Owner or -1 if you want to delete Existing Permissions.

The ShareResourceWithUsersAndGroups function Shares the Resource With all Provided Users and Groups with the Given permissionType.
```
err := helper.ShareResourceWithUsersAndGroups(ctx, client, "resource id", []string{"user 1 id"}, []string{"group 1 id"}, 7)
```
Note: Existing Permission of Users and Groups will be Adjusted to Fit the Type.

If you need to do something more Complicated like setting Users/Groups to different Type then you can Use ShareResource directly:
```
changes := []helper.ShareOperation{}

// Make this User Owner
changes = append(changes, ShareOperation{
	Type:  15,
	ARO:   "User",
	AROID: "user 1 id",
})

// Make this User Can Update
changes = append(changes, ShareOperation{
	Type:  5,
	ARO:   "User",
	AROID: "user 2 id",
})

// Delete This Users Current Permission
changes = append(changes, ShareOperation{
	Type:  -1,
	ARO:   "User",
	AROID: "user 3 id",
})

// Make this Group Read Only
changes = append(changes, ShareOperation{
	Type:  1,
	ARO:   "Group",
	AROID: "group 1 id",
})

err := helper.ShareResource(ctx, c, resourceID, changes)
```
Note: These Functions are Also Availabe for Folders (PRO)

## Full Example
This Example Creates a Resource, Searches for a User Named Test User, Checks that its Not itself and Shares the Password with the Test User if Nessesary:
```
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/speatzle/go-passbolt/api"
	"github.com/speatzle/go-passbolt/helper"
)

const passboltAddress = "https://passbolt.example.com"
const userPassword = "aStrongPassword"
const userPrivateKey = `
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.6.2
Comment: https://openpgpjs.org
klasd...
-----END PGP PRIVATE KEY BLOCK-----`

func main() {
	ctx := context.TODO()

	u, err := url.Parse(passboltAddress)
	if err != nil {
		panic(err)
	}

	client, err := api.NewClient(u, nil, "", userPrivateKey, userPassword)
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
		"This is a Account for the example test portal", // Description
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

	me, err := client.GetMe(ctx)
	if err != nil {
		panic(err)
	}

	if me.ID == users[0].ID {
		fmt.Println("I am the Test User, No Need to Share Password With myself")
		return
	}

	helper.ShareResourceWithUsersAndGroups(ctx, client, resourceID, []string{users[0].ID}, []string{}, 7)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Shared Resource With Test User %v\n", users[0].ID)
}
```

# TODO
- get a Passbolt Instance to Work in Github Actions
- write Integration Tests
- add ability to verify Server
- add helper functions for updating Groups