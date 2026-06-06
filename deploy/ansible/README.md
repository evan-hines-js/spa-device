# Installing a gate with Ansible

One playbook to stand up a spa-device gate on a fresh host: it ships **prebuilt**
artifacts (no Rust/LLVM toolchain on the protected host — see
[`BUILD.md`](../../BUILD.md)), self-provisions against the control plane, and
installs the persistent systemd unit.

```
deploy/ansible/
  gate.yml                  the playbook (build → install)
  inventory.example.ini     copy to inventory.ini and edit
  ansible.cfg
```

## What it does

1. **build** (on the `builder` host): runs `scripts/build-gate-release.sh` and
   fetches `spa-gate.o` + `spa-gated-<arch>` to `dist/` on the control node.
2. **install** (on each `gates` host): copies the binary, BPF object, and CA;
   runs `spa-gated provision …` to generate the gate's knock key and write
   `/etc/spa-gated/gated.toml`; installs and starts `spa-gated`.

The gate fetches its `gate_id` and trust anchor from the control plane on first
run, then cloaks the ports its signed bundle names.

## Inputs

This playbook is **control-plane-agnostic** — it takes the few things a gate can't
derive as variables:

| Var | Meaning |
|---|---|
| `gate_token` | one-time enrollment token, minted by the control plane (**`-e`**) |
| `argus_url` | control-plane base URL the gate provisions/polls against |
| `argus_ca` | path **on the control node** to the CA that signs the control plane's TLS |
| `spa_interface` | the gate's external NIC to attach XDP to (e.g. `ens18`) |
| `gate_address` | how clients reach this gate (default: the host's `ansible_host`) |
| `spa_suite` / `knock_port` | cipher suite (`modern`) / knock UDP port (`62201`) |

Re-running is safe: provisioning is skipped once `gated.toml` exists (it would mint
a new key). Force a fresh identity with `-e gate_reprovision=true`.

## Run

```sh
cp inventory.example.ini inventory.ini   # edit hosts + argus_url/argus_ca
ansible-playbook gate.yml -e gate_token=<ONE_TIME_TOKEN>
```

Build once, install many:

```sh
ansible-playbook gate.yml --tags build                       # refresh dist/
ansible-playbook gate.yml --tags install -e gate_token=<T>   # onboard a gate
```

A consumer can mint the token and call this in one shot — see
`argus/deploy/onboard-gate.sh` for the reference wrapper.

## Verify

```sh
ssh ubuntu@<gate> 'sudo journalctl -u spa-gated -n5 -o cat'   # startup, protected ports, floor
nmap -Pn -p22,1280,3022 <gate>                                # cloaked ports filtered, :22 open
```
