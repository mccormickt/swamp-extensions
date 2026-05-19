# swamp-extensions

A monorepo of [swamp](https://github.com/systeminit/swamp) extensions
authored by [@mccormickt](https://github.com/mccormickt). Each subdirectory
is a self-contained, publishable extension.

## Extensions

| Extension              | Kind   | Description                                                                                              |
| ---------------------- | ------ | -------------------------------------------------------------------------------------------------------- |
| [`@mccormick/aurae`](./aurae)   | driver | Runs swamp methods inside [aurae](https://github.com/aurae-runtime/aurae) cells via `aer`. Extensible to micro-VMs. |
| [`@mccormick/helios`](./helios) | models | Four models that manage an [illumos](https://illumos.org)/[Helios](https://github.com/oxidecomputer/helios) host over SSH: host, zfs, dladm, zone. |

Each extension has its own `README.md` with prerequisites, configuration,
and end-to-end usage examples.

## License

MIT — see [LICENSE](./LICENSE).
