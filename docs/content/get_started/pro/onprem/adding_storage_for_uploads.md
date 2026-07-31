---
title: "Adding Storage for Uploaded Files"
description: "Expand the storage available for uploaded files on a Docker Compose deployment without altering the deployment itself"
draft: false
weight: 11
audience: pro
---

Uploaded files live in the media directory on the host, and on a Docker Compose deployment the space available for them is whatever the VM's disk has left. Large uploads such as SBOMs can fill that disk. This page covers expanding the space without changing the deployment itself.

## Why this works at the OS level

The Docker Compose deployment bind mounts the host's media directory into the containers that need it, both the application containers and the nginx that serves uploaded files back to users. The containers read and write a path on the host, so whatever filesystem is mounted at that path is what they use. Mounting more capacity there is transparent to the application.

That is why the approach here is an operating system change rather than a deployment change. Keeping the Compose file that ships with your release unaltered keeps your install consistent with other on-premise deployments, and avoids losing the change when an upgrade replaces that file.

## Block storage, the straightforward option

Mounting an additional block device is the usual way to handle a full disk on Linux, and it is the option to reach for first. A NAS or SAN volume works, as does a cloud provider's block storage such as an Amazon EBS volume.

Separating application storage from the operating system disk is good practice generally, so you have two reasonable choices. Mount the device at the media directory to give uploads their own capacity, or mount it one level up at the deployment directory so all application data sits on a filesystem separate from the VM.

## Object storage, with caveats

Backing uploads with object storage such as Amazon S3 is feasible, and it removes the capacity ceiling entirely, but it is a less natural fit than a block device. Consider the following before choosing it.

Object storage is not a filesystem. S3 does not support random writes, appending to an existing file, or file locking. A FUSE layer papers over the gaps, but it is emulating semantics the underlying store does not have.

Latency is higher than a block device. That affects uploads, and because nginx serves uploaded files from the same directory, it affects downloads too.

It adds network dependencies. Depending on where the VM sits in your network, reaching the bucket may involve additional network traversal, and that path now has to be available for uploads to work.

Reboots need care. The bucket has to be mounted at boot, which introduces a timing relationship between the mount completing and DefectDojo starting. Depending on latency this can produce a hung reboot or a start with the mount not yet ready.

Permissions have to line up. The bucket's IAM permissions need to reconcile with the filesystem permissions the application needs to write uploads.

### Tools for mounting object storage

Three tools are commonly used to mount S3 as a filesystem on Linux.

`rclone mount` is stable, actively maintained, and offers virtual filesystem caching modes that handle read and write buffering well. Of the three, this is the one we would suggest if you go this route.

`goofys` is optimized for speed. It gets there by performing file creations and writes asynchronously and ignoring the operations S3 does not natively support, such as random writes and file locking.

`s3fs-fuse` is the most POSIX compatible of the three, supporting things like changing ownership and permissions, but mimicking a real filesystem makes it considerably slower than goofys.

## Moving the media directory to a new filesystem

This requires downtime, since the application must not be writing uploads while they are being copied.

1. Stop DefectDojo with `dojo-compose-cli app stop`, so nothing changes underneath you during the move.
2. Rename the existing media directory to keep it as a rollback point, for example moving `media` to `old-media` inside your deployment directory.
3. Create an empty directory at the original media path to act as the mount point.
4. Attach the new filesystem. The specifics depend on what you chose above, but it comes to three things: make the storage available to Linux, which for object storage means creating the bucket and its permissions; mount it at the media path; and make the mount survive a reboot, usually with an `/etc/fstab` entry or the equivalent for your tool.
5. Copy the old contents across, preserving ownership and permissions. `rsync -Pav` from the old directory to the new one does this and reports progress, which is useful when there is a lot to move.
6. Confirm the files arrived. For object storage, checking the bucket in your provider's console is the quickest way to be sure the mount is really writing where you think it is.
7. Start DefectDojo with `dojo-compose-cli app start` and upload a test file. If the upload fails, the container logs will say why, and permissions are the usual cause.

Keep the old directory until the test upload succeeds and you have confirmed that files migrated from it are readable in the UI. It is your way back if the new filesystem does not behave.

## Support scope

These are general recommendations. Adding storage to a VM is an operating system task, and the specifics of your chosen method, particularly a FUSE-mounted object store, are outside the scope of on-premise support. The approach is deliberately framed to keep your deployment consistent with every other on-premise install, leaving the Compose file we ship unaltered and solving the capacity problem at the OS layer where it belongs.

If you are weighing the options for your environment, contact [support@defectdojo.com](mailto:support@defectdojo.com) and we can talk through the tradeoffs before you commit to one.
