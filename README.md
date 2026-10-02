# NekoIMS
NekoIMS is a portable IMS client built on top of BareSIP in C++11 

### Dependencies (should be populated via cmake)
* libcurl
* BareSIP
* vo-amrwbenc
* opencore-amr
* https://github.com/nlohmann/json
* (optional) pcsclite for simcard-server

### Build
```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

On Windows, run the same commands from a Visual Studio developer prompt
(MSVC, x64 or ARM64). Git must be on `PATH`. Audio uses WASAPI (`audio_device`
defaults to `default`) instead of ALSA, and AMR is compiled in tree since
autotools isn't available.

### Config
Copy nekoims.example.json to nekoims.json and edit
* IMEI 
* Domain (ims.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org) or vzwims.com for Verizon  
* pcscf (from VPN or whatever value is relevant to your ims bearer if directly attached)
* msisdn (to your phone number)
### Control sockets
baresip's remote control interfaces are both off by default, but can be enabled as follows
* `"ctrl_tcp": true`: JSON commands and events over netstrings on
  `ctrl_tcp_listen` (default `127.0.0.1:4444`), e.g.
  `{"command":"dial","params":"+15551234567"}`
* `"httpd": true`: menu commands over HTTP on `http_listen` (default
  `127.0.0.1:8000`), e.g. `curl 'http://127.0.0.1:8000/?d+15551234567'`

Neither one supports auth, so anyone who can connect can place calls. Keep
them on localhost.

### SMS
SMS over IMS in both directions, in 3GPP (`application/vnd.3gpp.sms`) or
3GPP2 (`application/vnd.3gpp2.sms`, which Verizon uses) format. Received SMS
are acknowledged to the network and handed to baresip as `text/plain`
messages (console, ctrl_tcp `message` events), and in B2BUA mode also relayed
to the external UA.

```json
"sms": { "rx": "plain", "tx": "plain", "format": "auto", "smsc": "" }
```

* `rx`: what SIP clients receive. `plain` is the decoded text; SMS without a
  text form (WAP push, binary data) fall back to `binary_b64`, the original
  bytes as a data URI: `data:application/vnd.3gpp2.sms;base64,...`
* `tx`: what SIP clients send. `plain` text is encoded into an SMS here;
  `binary_b64` expects the same data URI form. A MESSAGE that is already
  `application/vnd.3gpp(2).sms` is sent as is either way
* `format`: `auto` sends in the format SMS were last received in (3GPP until
  one arrives), or force `3gpp` / `3gpp2`
* `smsc`: service centre URI or number to send to. By default, wherever the
  last received SMS came from
* `off` for `rx` or `tx` disables that direction

You can also send with the `sms` command, from the console, ctrl_tcp
(`{"command":"sms","params":"+15551234567 hi"}`) or httpd, or in B2BUA mode
with a SIP MESSAGE from the external UA to `<number>@<NekoIMS>`. The network's
verdict arrives as an SMS of its own: with `rx` `plain` it's reported as an
`sms` module event (`sent` / `failed`), with `binary_b64` it's delivered as
is. Only single-part messages can be sent for now (160 characters, or 70
outside the GSM/ASCII character set).

Unless `contact_features` is set explicitly, `+g.3gpp.smsip` is added to the
registration string so the network delivers the SMS over IMS. If you set
`contact_features`, add it yourself.

### B2BUA mode
With `"b2bua": {"enabled": true, ...}` NekoIMS runs headless and bridges calls
to an external SIP UA (desk phone, softphone, PBX trunk) instead of the sound
card. This is useful for peering with asterisk or using gnome-calls or another softphone. Note that this mode is likely filled with bugs.

* `username` / `password`: digest credentials the external UA uses for its
  REGISTER and INVITEs (no `password` means no authentication, only do that
  on a trusted network)
* `target`: optional fixed URI for incoming IMS calls, used when no UA is
  registered, e.g. `sip:100@192.168.1.20:5060`
* `audio_codecs`: codecs offered to the external UA (default
  `PCMU/8000,PCMA/8000`; `AMR-WB/16000` and `AMR/8000` also available)