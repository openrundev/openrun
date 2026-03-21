---
title: "Using SQLite as Storage for Web Server Static Content"
summary: "Why OpenRun uses a SQLite database instead of the local file system for static files."
date: 2024-10-25
---

{{< openrun-intro  >}}

## Background

OpenRun is built to serve web applications, primarily for internal tools. OpenRun provides functionality usually handled separately by a web server and an application server. When the development of OpenRun was started last year, one of the first decisions was how to store the application data (files) and metadata. The app metadata obviously made sense to store in a database, since apps are created dynamically. The app data (static files, app code, config files etc) is usually stored on the file system by most web servers.

## Using SQLite for serving files

For OpenRun, the decision was made to use [SQLite](https://www.sqlite.org/) for app files storage instead of using the file system. The reasoning was mainly to be able to do atomic version changes. When updating an app, since there could be lots of files being updated, using a database would allow all changes to be done atomically in a transaction. This would prevent broken web pages from being served during a version change.

OpenRun uploads all files to the SQLite database during app creation and updates. Files are uploaded from GitHub or from local disk. Only for [development mode]({{< ref "/docs/applications/lifecycle/#development-apps" >}}), the local file system is used.

## Benefits of using SQLite

The decision to use SQLite for file storage has provided lots of additional benefits (some unanticipated).

- **Transactional Updates** : This is the main benefit. Updating multiple files can be done in one transaction. Isolation ensures that there are no broken webapps during the update.

- **Deployment Rollbacks**: Another of the transactional benefits is the ability to roll back deployment in case of errors. If multiple apps are being updated, all of them can be rolled back in one go. Rolling back a database transaction is much easier than cleaning up files on the file system.

- **File De-duplication Across Versions**: OpenRun automatically [versions]({{< ref "docs/applications/overview/#app-listing" >}}) all updates. This can lead to lots of duplicate files. The file data is stored in a table with the schema

```sql
CREATE TABLE files (sha text, compression_type text, content blob, create_time datetime, PRIMARY KEY(sha));
```

The uncompressed content SHA256 hash is used as the primary key to store the file data. This means that even if multiple versions of an app have the same file, the file contents are stored only once.

- **De-duplication Across Apps** : Each production app in OpenRun has an [staging app]({{< ref "/docs/applications/lifecycle/#application-types" >}}). Apps can have multiple [previews apps]({{< ref "/docs/applications/lifecycle/#preview-apps" >}}). This can lead to lots of duplication of files. Using the database helps avoid all the duplication. Even across apps, there are files which have the same contents. Files are de-duplicated across apps also.

- **Easy Backups**: Using SQLite means that backups are easy. The state of the whole system, metadata and files can be backed up easily using SQLite backup tools like [Litestream](https://litestream.io/).

- **Content Hashing**: For content caching on the browser, web servers return a [ETag](https://en.wikipedia.org/wiki/HTTP_ETag) header. Using the database for files makes it easy to save the content SHA once during file upload without having to recompute it later.

- **Compression**: The file contents are saved [Brotli](https://en.wikipedia.org/wiki/Brotli) compressed in the SQLite table. The database approach has the advantage that contents can be saved in multiple formats easily. GZip compressed data and uncompressed data can be added by just adding a column in the `files` table.

## Performance

For OpenRun, the SQLite database approach provides great performance. There is no equivalent implementation using the file system to compare against, so a direct benchmark test is not done. Based on [benchmarking](https://www.sqlite.org/fasterthanfs.html) done by the SQLite team, SQLite can have better performance than direct file system use for some workloads.

## Multi-Node Support

OpenRun currently runs on a single node. When multi-node support is added later, the plan is to use a shared Postgres database instead of using local SQLite for metadata and file data storage. This will come with latency issues. The plan is to use a local SQLite database as a file cache to avoid latency while accessing Postgres.

## Why this approach is not more common?

One of the reasons most web servers use the file system is convenience. File updates can be done using any file system tool: rsync, tar etc work for copying files over. The other reason is probably historical: file systems are what were used before there were good in-process relational databases available. Using a database means some kind of API interface is required for uploading files, which is not always feasible.

{{<callout emoji="💬" >}}
Discussion thread on [Hacker News](https://news.ycombinator.com/item?id=41963996)
{{</callout>}}
