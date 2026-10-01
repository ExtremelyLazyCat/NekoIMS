enum class Platform {
    Windows,
    Linux,
};
#ifdef _WIN32
constexpr Platform kPlatform = Platform::Windows;
const char* const kAudioModule = "wasapi";
const char* const kConsoleModule = "wincons";
const char* const kDefaultAudioDevice = "default";
#else
constexpr Platform kPlatform = Platform::Linux;
const char* const kAudioModule = "alsa";
const char* const kConsoleModule = "stdio";
const char* const kDefaultAudioDevice = "plughw:0,0";
#endif