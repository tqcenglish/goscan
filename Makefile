build:
	cd cmd && go build -o ../deployments/goscan
linux:
	cd cmd && gox -osarch="linux/amd64"  -output ../deployments/goscan-linux