---
title: "Store Plugin"
weight: 300
summary: "Store plugin provides a managed document store interface for SQLite and PostgreSQL"
---

The `store.in` plugin provides a document store interface backed by SQLite or PostgreSQL. OpenRun creates the tables and indexes declared in `schema.star` when the store is initialized.

## Introduction

The `store.in` plugin automatically creates tables with the specified schema:

- Tables are created on first load unless they are already present, and are linked to the app.
- The tables use a document store interface. The data is stored as JSON(B) data types.
- Queries use a structured interface similar to the one provided by MongoDB. SQL injection is not possible, even if the application code is incorrectly written.

## Database Configuration

The default store database is separate from the server metadata database:

```toml {filename="openrun.toml"}
[plugin."store.in"]
db_connection = "sqlite:$OPENRUN_HOME/metadata/clace_app_store.db"
```

To use an existing PostgreSQL database, configure a connection whose account can create tables and indexes:

```toml {filename="openrun.toml"}
[plugin."store.in"]
db_connection = "postgres://openrun:password@db.example.com:5432/app_store?sslmode=require"
```

- The same Starlark store APIs work with either backend.
- Changing this setting selects another database; it does not migrate existing data.
- Back up the store database separately from the server metadata.
- Store tables are distinct from container app databases provisioned through [service bindings]({{< ref "docs/applications/servicebindings" >}}).

{{<callout type="warning" >}}
Production and its linked staging app share the same store tables. Staging writes therefore affect production data when write access is enabled (the default). Use [staging write controls]({{< ref "docs/applications/lifecycle/#write-mode-access" >}}) to restrict plugin writes, or a separate app for isolated test data. SQLite service bindings have a different model, with separate volumes for production and staging.
{{</callout>}}

## Schema Definition

The schema for the app is specified in the `schema.star` file in the root directory of the app code. The format of this file is like:

```python {filename="schema.star"}
type("bookmark",
     fields=[
         field("url", STRING),
         field("tags", LIST),
     ],
     indexes=[
         index(["url"], unique=True)
     ])

type("tag",
     fields=[
         field("tag", STRING),
         field("urls", LIST),
     ],
     indexes=[
         index(["tag"], unique=True)
     ])
```

Multiple types can be specified. Each type has a name, list of fields and list of indexes, and maps to one table in the underlying database.

- **Fields:** each field has a name and a type. The valid types are `INT`, `STRING`, `BOOLEAN`, `LIST` and `DICT`.
- **Indexes:** the `indexes` argument of `type` is optional. Each index is specified as a list of field names. Adding `:desc` to the field name changes the index to be sorted descending instead of default ascending (`:asc` is accepted and is the default). Setting the `unique` property to `True` makes it a unique index.

## Schema Design

SQL tables are used as underlying storage, but joins are not supported by the `store.in` interface. The schema design to use would be same as schema used for a [document database](https://www.mongodb.com/docs/manual/data-modeling/). Since `LIST` and `DICT` data types are supported, de-normalized schema is recommended instead of normalized schema.

## Store Types

The type information is read from the schema file and schema types are automatically created for the app:

- The `doc` namespace has type objects for each type. For the previous example, the two types created are `doc.bookmark` and `doc.tag`.
- The `table` namespace has entries which reference the table names for the types. For the previous example, the two table names available are `table.bookmark` and `table.tag`.

This allows creating objects and persisting them using the store API by doing:

```python {filename="app.star"}
bookmark = doc.bookmark(
    url="http://openrun.dev", tags=["webapps", "tools"])
ret = store.insert(table.bookmark, bookmark)
```

## Store APIs

The APIs in the `store.in` plugin and their arguments and response are:

| API | Type | Args | Response Value | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **begin** | Read | - | - | Begin a new transaction |
| **commit** | Write | - | - | Commit active transaction |
| **rollback** | Read | - | - | Rollback active transaction |
| **select_by_id** | Read | table: string <br> id : int | doc | Select one record by id |
| **select** | Read | table: string <br> filter : dict <br> sort : list string <br> offset : int <br> limit : int (default 10,000) | doc iterator | Select by filter |
| **select_one** | Read | table: string <br> filter : dict | doc | Select one by filter |
| **count** | Read | table: string <br> filter : dict | int | Count entries by filter |
| **insert** | Write | table: string <br> entry : doc | id : int | Insert a document |
| **update** | Write | table: string <br> entry : doc | count : int | Update a document |
| **delete_by_id** | Write | table: string <br> id : int | count : int | Delete one document by id |
| **delete** | Write | table: string <br> filter : dict | count : int | Delete multiple docs by filter |

## Transactions

The transaction handling APIs `begin`, `commit` and `rollback` take no arguments. All the other APIs take the table name as the first argument.

- The transaction created by `begin` is saved in the request state; there is no need to pass the transaction manually to subsequent API calls.
- Only one transaction can be active at a time, a second `begin` fails.
- The transaction `rollback` is automatically done at the end of the API handler if `commit` is not done explicitly.
- `select_by_id` and `select_one` fail with an error when no matching entry is found. `update` and `delete_by_id` return a count of zero in that case.

## Automatic Fields

All tables have some fields added automatically. These are:

| Field | Type | Notes |
| :--- | :--- | :--- |
| \_id | int | Primary key |
| \_version | int | Schema version |
| \_created_by | string | User id |
| \_updated_by | string | User id |
| \_created_at | int | Creation time, Unix epoch milliseconds |
| \_updated_at | int | Last update time, Unix epoch milliseconds |

These fields can be accessed like regular user defined fields in the store APIs. So `bookmark._id` can be used the way `bookmark.url` is used in all the APIs. `_created_by` and `_updated_by` are the user id of the request which made the `insert` or `update` call, `anonymous` when the request has no authenticated user.

## Iterators

The `select` API returns a document iterator. Use a regular python `for` loop to iterate on the entries. For example,

```python {filename="app.star"}
ret = store.select(table.bookmark, {}, limit=100,
                    sort=["_created_at:desc"])
bookmarks = []
for row in ret.value:
    bookmarks.append(row)
```

Iterating till the end of the loop automatically closes the iterator. Returning from a handler without closing an iterator causes the handler to fail: the OpenRun platform closes the iterator automatically to prevent a resource leak, and the API failure indicates to the developer that the code needs to be fixed to explicitly close the iterator.

{{<callout type="warning" >}}
**Note:** The iterator cannot be directly returned from the handler. A list needs to be created and populated if the entries need to be passed to the template.
{{</callout>}}

## Select Limits and Sort

For the `select` API:

- **limit:** the default limit value is 10,000. The API can pass a different limit value if required. The maximum value allowed is 100,000; passing a limit beyond that results in an API failure.
- **sort:** a list of strings. For example, `["age", "city"]` is sorted on age and city ascending. `["age", "city:desc"]` is sorted on age ascending and city descending.

## Filter

The `select`, `select_one`, `count` and `delete` APIs take a filter parameter. The filter has to be specified as a dict. The format of the filter is similar to the format used by MongoDB. The advantage of this over a SQL expression is that there is no possibility of SQL injection, even with an improperly written application.

The filter is a dictionary whose keys name the fields to test. A scalar value tests equality. A dictionary value specifies operators to apply to that field. For example:

| Filter | SQL where clause | Notes |
| :--- | :--- | :--- |
| `{"age": 30}` | `age = ?` | Parameter bound to 30 |
| `{"age": 30, "city": "New York", "state": "California"}` | `age = ? AND city = ? AND state = ?` | With the appropriate bindings |
| `{"age": 30, "$or": [{"city": "New York"}, {"state": "California"}]}` | `age = ? AND ( city = ? OR state = ? )` | Or condition |
| `{"age": {"$gt": 30}}` | `age > ?` | Inequality condition |
| `{"age": {"$gte": 18, "$lt": 65}}` | `age >= ? AND age < ?` | Multiple operators on one field are combined with AND |
| `{"age": {"$or": [{"$lt": 18}, {"$gt": 65}]}}` | `( age < ? OR age > ? )` | A logical operator within a field condition, each entry having one operator |

The logical operators supported are `$AND` and `$OR`, case insensitive.

The filter operators supported (lower case) are

| Filter | SQL | Notes |
| :--- | :--- | :--- |
| $gt | > | |
| $lt | < | |
| $gte | >= | |
| $lte | <= | |
| $eq | = | Default when value is not a dict |
| $ne | != | |
| $like | like | Value has to be passed with % added, it is not added automatically. For example `"%test%"` |
