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

Without overriding the Autotools' defaults, the module will be installed in `/usr/local/lib/security`. This is most likely not going to work and you will need to specify either installation prefix with `--prefix` or library directory with ` --libdir` to be extra precise. For example `./configure --prefix=/` and `./configure --libdir=/lib` both work on my Arch machine, but on Debian I only succeeded with `./configure --libdir=/usr/lib/x86_64-linux-gnu`. 

## Usage
After the module is installed, you have to configure the service of your choice to use it. For example using it with SSH would require modifying `/etc/pam.d/sshd`. Typical usage would look like this:
```
auth        sufficient      pam_oidc.so <mode> <options>
```
All mode and options are described below. For more information on how to configure PAM to your liking, see `pam.conf(5)`. 

### `id_token` mode
In this mode user is prompted for OIDC ID token (JWT format). Deciding how to obtain the token is user's responsibility, but author recommends looking at [oidc-agent](https://github.com/indigo-dc/oidc-agent) project.

The token's signature is verified using JWK (JSON Web Key) Set acquired from dedicated OpenID Provider's (OP's) endpoint. 

Authorization right now works in very simplified way. User is only granted access if requested account's username equals to "user" string + the value of user's "sub" claim (e.g. "user101977677136526966383").

Default OpenID Provider (OP) used is Google. If you'd like to change it, this mode accepts optional `--openid-config-url` option where you can specify URL pointing to OpenID Provider Configuration Information document (the one with path ending in `/.well-known/openid-configuration`).

### `poll` mode
In this mode user is shown an URL and a code.  The user should visit the URL, paste the provided code and login using the OIDC flow.

Authorization is based on user's `sub` claim and is described in the subsection above.

To use this mode you have to obtain OAuth 2.0 credentials from OpenID provider of your choice (for now only Google is supported though). You will need to provide client ID using and client secret using `--client-id` and `--client-secret` option respectively. Both these options are required in this mode.

### `local_auth` mode
In this mode user is prompted for OIDC access token. Deciding how to obtain the token is user's responsibility, but author recommends looking at [mccli](https://github.com/dianagudu/mccli) project.

This mode delegates the authentication and authorization to [motley_cue](https://github.com/dianagudu/motley_cue) service. The service's endpoint is configured using optional `--verify-endpoint` option. The default value is http://localhost:8080/verify_user.