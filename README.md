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

### Config
Copy nekoims.example.json to nekoims.json and edit
* IMEI 
* Domain (ims.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org) or vzwims.com for Verizon  
* pcscf (from VPN or whatever value is relevant to your ims bearer if directly attached)
* msisdn (to your phone number)