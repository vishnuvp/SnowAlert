## AWS Accounts List Connector

The AWS Accounts List Connector allows you to assume-role into the master account for your AWS Organization and export a list of all of the accounts in your organization into Snowflake. This list can then be used to power other connectors, such as the AWS Asset Inventory connector; instead of setting up the Inventory connector for each of your accounts, you can set up the Inventory connector with the Accounts table, and it will export your inventory for each account in that table.

### AWS Accounts List Connector Role Setup

The AWS Accounts List Connector has three required options: A Source Role ARN, a Destination Role ARN, and a Destination Role External ID. The source role should be a role in the AWS Account where SnowAlert is running that SnowAlert can use; the idea is that the connector will use this role to STS Assume-Role into the Destination Role, authenticated by the Destination Role External ID provided.

As such, the Destination Role should be in the master account for your AWS Organization, and have a trust policy which allows it to be assumed by the Source Role, along with the correct External ID.

### AWS Accounts powering Inventories

In order to combine the AWS Accounts List Connector with the AWS Asset Inventory Connector, a slightly more complicated setup is required. You can provide the connector with the Source Role ARN, a Destination Role Name, a Destination Role External ID, and an AWS Accounts List Connection Table.

When the Inventory connector runs, the first thing it will do is query your Accounts connection table to get an up-to-date list of your AWS Accounts. Next, for each account in that list, it will attempt to STS Assume-Role to the Destination Role Name you provided (Note that you provided a Role Name, as opposed to a Role ARN). If you have created a role with that name in the account in question and made it assumable by the source role you specified, the Asset Inventory Connector will successfully hop into the destination role, list the assets it's looking for, and ingest that data to Snowflake. Then it will continue on with the next account in the table.

This means that instead of setting up the connector for each account (and having to manage one connection table per asset type per account), you can set up one connection table for your AWS Organization, and you just have to set up the destination role in each account where you want to export Asset Inventory data.
