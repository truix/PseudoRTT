#pragma once

#include <string>
#include <vector>

class WifiRTT {
 public:
  WifiRTT() = default;
  ~WifiRTT() = default;

  int RTT(const std::string& target_BSSID);

 private:
  void Cleanup();
  bool InitWifiCardInMonitorMode();
  bool InitPacketCapture();
  int SendAuthenticationRequest(const std::string& target_BSSID);
  int GetRadiotapHeaderLength(const u_char* frame);
  const u_char* CaptureNextFrame();
  bool IsAuthenticationResponse(const std::vector<uint8_t>& frame, const std::string& target_BSSID);
  std::vector<uint8_t> ConvertBSSIDStringToBytes(const std::string& bssid);

  pcap_t* handle_;
};
