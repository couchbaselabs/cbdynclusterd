#!/bin/bash

VERSION=${1:-5.0.0}
BUILD=${2:-3217}
FLAVOR=${3:-spock}
if [ "$BUILD" = "ga" ]; then
	docker build \
	--build-arg VERSION=${VERSION} \
	--build-arg BUILD_NO=${BUILD} \
	--build-arg FLAVOR=${FLAVOR} \
	--build-arg BUILD_PKG=couchbase-server-enterprise-$VERSION-centos7.x86_64.rpm \
	--build-arg BASE_URL=http://latestbuilds.service.couchbase.com/builds/releases/$VERSION/$BUILD_PKG \
	-t couchbase_${VERSION}-${BUILD}.centos7 .
else
	docker build \
	--build-arg VERSION=${VERSION} \
	--build-arg BUILD_NO=${BUILD} \
	--build-arg FLAVOR=${FLAVOR} \
	-t couchbase_${VERSION}-${BUILD}.centos7 .
fi
