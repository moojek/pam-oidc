# pam_oidc

`pam_oidc` is a PAM module that incorporates OIDC to your Linux login. It is primarily intended to use with SSH and features a few modes of operation.

## Installation

The project is currently not packaged in any distribution. 

You can build and install following the standard procedure:
```
./configure
make
make install
```

If you are building from a git clone (not a distributed tarball), you will need to set up Autotools first by running `autoreconf -fi`.

Without overriding the Autotools' defaults, the module will be installed in `/usr/local/lib/security`. This is most likely not going to work and you will need to specify either installation prefix with `--prefix` or library directory with ` --libdir` to be extra precise. For example `./configure --prefix=/` and `./configure --libdir=/lib` both work on my Arch machine and on Debian I succeeded with `./configure --prefix=/` and `./configure --libdir=/usr/lib/x86_64-linux-gnu`. 

## Usage



<!-- ## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate. -->

<!-- ## License

[MIT](https://choosealicense.com/licenses/mit/) -->