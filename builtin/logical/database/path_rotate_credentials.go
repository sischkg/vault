package database

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
)

func pathRotateCredentials(b *databaseBackend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "rotate-root/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of this database connection",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateCredentialsUpdate(),
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
			},

			HelpSynopsis:    pathCredsCreateReadHelpSyn,
			HelpDescription: pathCredsCreateReadHelpDesc,
		},
		&framework.Path{
			Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the static role",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateRoleCredentialsUpdate(),
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
			},

			HelpSynopsis:    pathCredsCreateReadHelpSyn,
			HelpDescription: pathCredsCreateReadHelpDesc,
		},
	}
}

func (b *databaseBackend) pathRotateCredentialsUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := data.Get("name").(string)
		if name == "" {
			return logical.ErrorResponse(respErrEmptyName), nil
		}

		config, err := b.DatabaseConfig(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}

		// Prepare static user config in event of needing to roll back the rotated password
		userConfig := dbplugin.StaticUserConfig{
			Username: config.ConnectionDetails["username"].(string),
			Password: config.ConnectionDetails["password"].(string),
		}

		db, err := b.GetConnection(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}

		connectionDetails, err := db.RotateRootCredentials(ctx, config.RootCredentialsRotateStatements)
		if err != nil {
			return nil, err
		}

		config.ConnectionDetails = connectionDetails
		entry, err := logical.StorageEntryJSON(fmt.Sprintf("config/%s", name), config)
		if err != nil {
			return nil, err
		}

		if putErr := req.Storage.Put(ctx, entry); putErr != nil {
			// Root credentials have been rotated and storage put has failed
			// Roll back rotation of credentials to original to avoid database lockout

			// Clear the current connection
			if err := b.ClearConnection(name); err != nil {
				b.Logger().Error("error closing the database plugin connection", "err", err)
				return nil, err
			}

			// Get a new connection using the new configuration with newly rotated password
			dbc, err := b.GetConnectionForConfig(ctx, name, config)
			if err != nil {
				return nil, err
			}

			// Roll back password to that before the rotation
			_, _, err = dbc.SetCredentials(ctx, dbplugin.Statements{}, userConfig)
			if err != nil {
				return nil, err
			}

			// Close the plugin
			if err := b.ClearConnection(name); err != nil {
				b.Logger().Error("error closing the database plugin connection", "err", err)
				return nil, err
			}

			return nil, putErr
		}

		// Close the plugin
		if err := b.ClearConnection(name); err != nil {
			b.Logger().Error("error closing the database plugin connection", "err", err)
		}

		return nil, nil
	}
}

func (b *databaseBackend) pathRotateRoleCredentialsUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := data.Get("name").(string)
		if name == "" {
			return logical.ErrorResponse("empty role name attribute given"), nil
		}

		role, err := b.StaticRole(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return logical.ErrorResponse("no static role found for role name"), nil
		}

		// In create/update of static accounts, we only care if the operation
		// err'd , and this call does not return credentials
		item, err := b.popFromRotationQueueByKey(name)
		if err != nil {
			item = &queue.Item{
				Key: name,
			}
		}

		resp, err := b.setStaticAccount(ctx, req.Storage, &setStaticAccountInput{
			RoleName: name,
			Role:     role,
		})
		if err != nil {
			b.logger.Warn("unable to rotate credentials in rotate-role", "error", err)
			// Update the priority to re-try this rotation and re-add the item to
			// the queue
			item.Priority = time.Now().Add(10 * time.Second).Unix()

			// Preserve the WALID if it was returned
			if resp.WALID != "" {
				item.Value = resp.WALID
			}
		} else {
			item.Priority = resp.RotationTime.Add(role.StaticAccount.RotationPeriod).Unix()
		}

		// Add their rotation to the queue
		if err := b.pushItem(item); err != nil {
			return nil, err
		}

		return nil, nil
	}
}

const pathRotateCredentialsUpdateHelpSyn = `
Request to rotate the root credentials for a certain database connection.
`

const pathRotateCredentialsUpdateHelpDesc = `
This path attempts to rotate the root credentials for the given database. 
`

const pathRotateRoleCredentialsUpdateHelpSyn = `
Request to rotate the credentials for a static user account.
`
const pathRotateRoleCredentialsUpdateHelpDesc = `
This path attempts to rotate the credentials for the given static user account.
`
