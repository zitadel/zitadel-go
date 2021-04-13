#! /bin/sh

set -eux

cd $GOPATH/src/github.com/caos/zitadel-go/tools
for imp in `cat tools.go | grep "_" | sed -E "s/_ \"(.*.+)\"/\1/g"`; do
    echo "installing $imp"
    go install $imp
done
cd -