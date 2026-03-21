---
title: "Store Plugin"
weight: 300
summary: "Store plugin provides a document store interface for SQLite and Postgres"
---

The `store.in` plugin provides a document store interface to work with SQLite tables (PostgreSQL support is coming soon). The goal for the store plugin is to support a full managed interface, creating the app automatically creates the tables required for the app.

## Introduction

The `store.in` plugins automatically creates tables with the specified schema. The tables are created on first load unless they are already present. The tables are linked to the app. The tables use a document store interface. The data is stored as JSON(B) data types. To query the data, a structured interface is used similar to the one provided by MongoDB. The advantage of this approach is that SQL injection is not possible, even if the application code is incorrectly written.

## Schema Definition

The schema for the app is specified in the `schema.star` file in the root directory of the app code. The format of this file is like:

```python {filename="app.star"}
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

Multiple types can be specified. Each type has a name, list of fields and list of indexes. Each field has a name and a type, the valid types are `INT`, `STRING`, `BOOLEAN`, `LIST` and `DICT`.

Each type maps to one table in the underlying database. Indexes can be created on the fields. Each index is specified as list of field names. Adding `:desc` to the field name changes the index to be sorted descending instead of default ascending. Setting `unique` property to `True` makes it an unique index.

## Schema Design

SQL tables are used as underlying storage, but joins are not supported by the `store.in` interface. The schema design to use would be same as schema used for a [document database](https://www.mongodb.com/developer/products/mongodb/mongodb-schema-design-best-practices/). Since `LIST` and `DICT` data types are supported, de-normalized schema is recommended instead of normalized schema.

## Store Types

The type information is read from the schema file and schema types are automatically created for the app. The `doc` namespace has type objects for each type. For the previous example, the two types created are `doc.bookmark` and `doc.tag`. The `table` namespace also has entry populated which reference the table names for the type. For the previous example, the two table names available are `table.bookmark` and `table.tag`. This allows creating objects and persisting them using the store API by doing:

```python {filename="app.star"}
bookmark = doc.bookmark(
    url="http://openrun.dev", tags=["webapps", "tools"])
ret = store.insert(table.bookmark, bookmark)
```

## Store APIs

The APIs in the `store.in` plugin and their arguments and response are:

|       API        | Type  |                                                     Args                                                     | Response Value |             Notes              |
| :--------------: | :---: | :----------------------------------------------------------------------------------------------------------: | :------------: | :----------------------------: |
|    **begin**     | Read  |                                                      -                                                       |       -        |    Begin a new transaction     |
|    **commit**    | Write |                                                      -                                                       |       -        |   Commit active transaction    |
|   **rollback**   | Read  |                                                      -                                                       |       -        |  Rollback active transaction   |
| **select_by_id** | Read  |                                         table: string <br> id : int                                          |      doc       |    Select one record by id     |
|    **select**    | Read  | table: string <br> filter : dict <br> sort : list string <br> offset : int <br> limit : int (default 10,000) |  doc iterator  |        Select by filter        |
|  **select_one**  | Read  |                                       table: string <br> filter : dict                                       |      doc       |      Select one by filter      |
|    **count**     | Read  |                                       table: string <br> filter : dict                                       |      int       |    Count entries by filter     |
|    **insert**    | Write |                                        table: string <br> entry : doc                                        |    id : int    |       Insert a document        |
|    **update**    | Write |                                        table: string <br> entry : doc                                        |  count : int   |       Update a document        |
| **delete_by_id** | Write |                                         table: string <br> id : int                                          |  count : int   |   Delete one document by id    |
|    **delete**    | Write |                                       table: string <br> filter : dict                                       |  count : int   | Delete multiple docs by filter |

## Transactions

The transaction handling APIs `begin`, `commit` and `rollback` take no arguments. All the other APIs take the table name as the first argument. The transaction created by the `begin` is saved in a thread local, there is no need to pass the transaction manually to subsequent API calls. The transaction `rollback` is automatically done at the end of the API handler if `commit` is not done explicitly.

## Automatic Fields

All tables have some fields added automatically. These are:

|    Field     |   Type    |     Notes      |
| :----------: | :-------: | :------------: |
|     \_id     |    int    |  Primary key   |
|  \_version   |    int    | Schema version |
| \_created_by |  string   |    User id     |
| \_updated_by |  string   |    User id     |
| \_created_at | timestamp |                |
| \_updated_at | timestamp |                |

These fields can be accessed like regular user defined field in the store APIs. So `bookmark._id` can be used the way `bookmark.url` is used in all the APIs.

## Iterators

The `select` API returns a document iterator. Use a regular python `for` loop to iterate on the entries. For example,

```python {filename="app.star"}
ret = store.select(table.bookmark, {}, limit=100,
                    sort=["_created_at:desc"])
bookmarks = []
for row in ret.value:
    bookmarks.append(row)
```

Iterating till the end of the loop automatically closes the iterator. Returning from a handler without closing an iterator will cause the handler to fail. The iterator is automatically closed by the OpenRun platform to prevent a resource leak. The API failure is used to indicate to the developer that the code needs to be fixed to explicitly close the iterator.

{{<callout type="warning" >}}
**Note:** The iterator cannot be directly returned from the handler. A list needs to be created and populated if the entries need to be passed to the template.
{{</callout>}}

## Select Limits and Sort

For the `select` API, a limit of 10,000 is set as the default limit value. The API can pass a different limit value if required. The maximum value allowed for the limit is 100,000. Passing a limit beyond that will result in an API failure.

The sort argument can be used to sort the result for the `select` API. The argument is a list of strings. For example, `["age", "city"]` is sorted on age and city ascending. `["age", "city:desc"]` is sorted on age ascending and city descending.

## Filter

The `select`, `select_one`, `count` and `delete` APIs take a filter parameter. The filter has to be specified as a dict. The format of the filter is similar to the format used by MongoDB. The advantage of this over a SQL expression is that there is no possibility of SQL injection, even with an improperly written application.

The filter is specified as a list diction, the keys are the names of the field to apply the condition on. The value can be a value, in which case it is treated as a equality match. If the value is an diction, then the it is treated as a expression to apply on the specified field.

For example, a filter `{"age": 30}` is equivalent to sql where clause `age = ?` with the parameter bound to 30. Filter `{"age": 30, "city": "New York", "state": "California"}` is same as sql `age = ? AND city = ? AND state = ?`, with the appropriate bindings. To express an or condition, do filter as `{"age": 30, "$or": [{"city": "New York"}, {"state": "California"}]}`. That translates to `age = ? AND ( city = ? OR state = ? )`

To express an inequality condition, do `{"age": {"$gt": 30}}` which becomes `age > ?`.

The logical operators supported are `$AND` and `$OR`, case insensitive.

The filter operators supported (case insensitive) are

| Filter | SQL  |                                              Notes                                              |
| :----: | :--: | :---------------------------------------------------------------------------------------------: |
|  $GT   |  >   |                                                                                                 |
|  $LT   |  <   |                                                                                                 |
|  $GTE  |  >=  |                                                                                                 |
|  $LTE  |  <=  |                                                                                                 |
|  $EQ   |  =   |                                Default when value is not a dict                                 |
|  $NE   |  !=  |                                                                                                 |
| $LIKE  | like | Value has to be passed with % added, <br> it is not added automatically. For example `"%test%"` |
