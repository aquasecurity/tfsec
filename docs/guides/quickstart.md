## Using as a command line tool

The easiest way to run `tfsec` is to run it in the directory you want to scan.

```bash
tfsec
```

`tfsec` will traverse the directory till it finds a valid [Terraform] file; the directory it finds this file in will be considered to the working directory.

If you want to run on a specific location, this can be passed as an argument;

```bash
tfsec ./tf/prod
```


The exit status will be non-zero if tfsec finds problems, otherwise the exit status will be zero.



## Use with Docker

As an alternative to installing and running tfsec on your system, you may
run tfsec in a Docker container.

To run:

```bash
docker run --rm -it -v "$(pwd):/src" aquasec/tfsec /src
```

## Using in CI

`tfsec` can be added to any CI pipeline as a command with the exit code dictating if it breaks the build. 

We do provide a [GitHub Action] that will also upload the results to GitHub code scanning UI.


## Passing Arguments

This page only covers the basics of what `tfsec` can do - much more is achievable using the arguments on the [Parameters] page.



[Terraform]: https://www.terraform.io
[GitHub Action]: ../github-actions/github-action
[Parameters]: ../usage
