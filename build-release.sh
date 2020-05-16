#!/bin/bash
sum="sha1sum"

if ! hash sha1sum 2>/dev/null; then
	if ! hash shasum 2>/dev/null; then
		echo "I can't see 'sha1sum' or 'shasum'"
		echo "Please install one of them!"
		exit
	fi
	sum="shasum"
fi

[[ -z $upx ]] && upx="echo pending"
if [[ $upx == "echo pending" ]] && hash upx 2>/dev/null; then
	upx="upx -9"
fi

VERSION=$(git describe --tags)
LDFLAGS="-s -w"
GCFLAGS=""

OSES=(linux darwin windows freebsd)
ARCHS=(amd64 386)

mkdir bin


for os in ${OSES[@]}; do
	for arch in ${ARCHS[@]}; do
		suffix=""
		if [ "$os" == "windows" ]
		then
			suffix=".exe"
		fi

		build () {
			env CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -v -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o $1_${os}_${arch}${suffix} ./$1
			$upx $1_${os}_${arch}${suffix} >/dev/null
			tar -zcf bin/$1-${os}-${arch}-$VERSION.tar.gz $1_${os}_${arch}${suffix}
			$sum bin/$1-${os}-${arch}-$VERSION.tar.gz
		}
		build 'dnstt-client'
		build 'dnstt-server'
	done
done
