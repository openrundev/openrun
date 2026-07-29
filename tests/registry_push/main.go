// registry_push copies a saved container image archive to a registry. It exists
// for the Kubernetes test harness so an HTTP test registry does not have to be
// added to the runner machine's Docker daemon configuration.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func main() {
	insecure := flag.Bool("insecure", false, "push to the registry over plain HTTP")
	tarPath := flag.String("tar", "", "path to an image archive produced by docker save")
	flag.Parse()
	if flag.NArg() != 1 || *tarPath == "" {
		fmt.Fprintln(os.Stderr, "usage: registry_push [--insecure] --tar PATH IMAGE")
		os.Exit(2)
	}

	imageName := flag.Arg(0)
	source, err := name.NewTag(imageName)
	if err != nil {
		fatalf("parse source image reference: %v", err)
	}
	image, err := tarball.ImageFromPath(*tarPath, &source)
	if err != nil {
		fatalf("read image archive: %v", err)
	}

	var nameOptions []name.Option
	if *insecure {
		nameOptions = append(nameOptions, name.Insecure)
	}
	destination, err := name.ParseReference(imageName, nameOptions...)
	if err != nil {
		fatalf("parse destination image reference: %v", err)
	}
	if err := remote.Write(destination, image, remote.WithAuth(authn.Anonymous)); err != nil {
		fatalf("push image: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
