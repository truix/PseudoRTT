#include "WifiRTT.h"
#include "Include.h"
#include <array>
#include <chrono>
#include <iostream>
#include <sstream>

int WifiRTT::RTT(const std::string& target_BSSID) {
    InitWifiCardInMonitorMode();
    InitPacketCapture();

    SendAuthenticationRequest(target_BSSID);

    std::chrono::steady_clock::time_point start_time = std::chrono::high_resolution_clock::now();
    std::chrono::steady_clock::time_point end_time;

    while (true) {
        const u_char* captured_data = CaptureNextFrame();
        int radiotap_length = GetRadiotapHeaderLength(captured_data);
        std::vector<uint8_t> frame(captured_data, captured_data + radiotap_length);

        if (IsAuthenticationResponse(frame, target_BSSID)) {
            end_time = std::chrono::high_resolution_clock::now();
            break;
        }
    }

    auto rtt = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
    Cleanup();
    return rtt.count();
}

bool WifiRTT::IsAuthenticationResponse(const std::vector<uint8_t>& frame, const std::string& target_BSSID) {
    int radiotap_length = frame[2] | (frame[3] << 8);

    if (frame.size() < static_cast<size_t>(radiotap_length) + 24) {
        return false;
    }

    uint8_t type = (frame[radiotap_length] >> 2) & 0x3;
    uint8_t subtype = (frame[radiotap_length] >> 4) & 0xF;
    if (type != 0 || subtype != 0xb) {
        return false;
    }

    std::vector<uint8_t> bssid_bytes = ConvertBSSIDStringToBytes(target_BSSID);
    for (int i = 0; i < 6; ++i) {
        if (frame[radiotap_length + 16 + i] != bssid_bytes[i]) {
            return false;
        }
    }

    return true;
}

const u_char* WifiRTT::CaptureNextFrame() {
    struct pcap_pkthdr header;
    const u_char* packet = pcap_next(handle_, &header);

    if (packet == nullptr) {
        std::cerr << "Error: " << pcap_geterr(handle_) << std::endl;
        return nullptr;
    }

    return packet;
}

void WifiRTT::Cleanup() {
    if (handle_ != nullptr) {
        if (pcap_set_rfmon(handle_, 0) != 0) {
            std::cerr << "Error: " << pcap_geterr(handle_) << std::endl;
        }

        pcap_close(handle_);
        handle_ = nullptr;
    }
}

int WifiRTT::GetRadiotapHeaderLength(const u_char* frame) {
    return frame[2] | (frame[3] << 8);
}

bool WifiRTT::InitWifiCardInMonitorMode() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error: " << errbuf << std::endl;
        return false;
    }

    pcap_if_t* wifi_dev = nullptr;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        if (strstr(d->description, "Wi-Fi")) {
            wifi_dev = d;
            break;
        }
    }

    if (!wifi_dev) {
        std::cerr << "No Wi-Fi device found." << std::endl;
        return false;
    }

    handle_ = pcap_create(wifi_dev->name, errbuf);
    if (handle_ == nullptr) {
        std::cerr << "Error: " << errbuf << std::endl;
        return false;
    }

    Cleanup();

    handle_ = pcap_create(wifi_dev->name, errbuf);
    if (handle_ == nullptr) {
        std::cerr << "Error: " << errbuf << std::endl;
        return false;
    }

    if (auto ret = pcap_can_set_rfmon(handle_) != 0) {
        std::cerr << "Device Cannot be set in monitor mode." << std::endl;
    }

    auto ret = pcap_set_rfmon(handle_, 0);
    if (ret != PCAP_ERROR_ACTIVATED && ret != 0) {
        std::cerr << "Failed to set device in monitor mode." << std::endl;
        return false;
    }

    if (pcap_set_snaplen(handle_, 2048) != 0) {
        std::cerr << "Error: " << pcap_geterr(handle_) << std::endl;
        return false;
    }

    if (pcap_set_promisc(handle_, 1) != 0) {
        std::cerr << "Error: " << pcap_geterr(handle_) << std::endl;
        return false;
    }

    if (pcap_set_timeout(handle_, 512) != 0) {
        std::cerr << "Error: " << pcap_geterr(handle_) << std::endl;
        return false;
    }

    int status = pcap_activate(handle_);
    if (status < 0) {
        std::cerr << "Error: " << pcap_geterr(handle_) << std::endl;
    }

    pcap_freealldevs(alldevs);
    return true;
}

bool WifiRTT::InitPacketCapture() {
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    const char* filter_exp = "type mgt subtype auth";  
    if (pcap_compile(handle_, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error: Could not parse filter " << filter_exp << ": " << pcap_geterr(handle_) << std::endl;
        return false;
    }

    if (pcap_setfilter(handle_, &fp) == -1) {
        std::cerr << "Error: Could not install filter " << filter_exp << ": " << pcap_geterr(handle_) << std::endl;
        return false;
    }

    pcap_freecode(&fp);
    return true;
}

int WifiRTT::SendAuthenticationRequest(const std::string& target_BSSID) {
    std::array<uint8_t, 8> radiotap_header =
    { 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00 };

    // 802.11 MAC header for an authentication frame.
    std::array<uint8_t, 24> mac_header = {
        0xb0, 0x00,                         // Frame control
        0x00, 0x00,                         // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination address (broadcast)
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // Source address 
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb  // BSSID
    };


    std::vector<uint8_t> bssid_bytes = ConvertBSSIDStringToBytes(target_BSSID);
    if (bssid_bytes.size() != 6) {
        std::cerr << "Invalid BSSID format." << std::endl;
        return -1;
    }
    std::copy(bssid_bytes.begin(), bssid_bytes.end(), mac_header.begin() + 16);

    // Authentication frame body for open system authentication.
    std::array<uint8_t, 6> auth_body = { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };

    // Construct the full frame.
    std::vector<uint8_t> frame;
    frame.insert(frame.end(), radiotap_header.begin(), radiotap_header.end());
    frame.insert(frame.end(), mac_header.begin(), mac_header.end());
    frame.insert(frame.end(), auth_body.begin(), auth_body.end());

   
    if (pcap_sendpacket(handle_, frame.data(), frame.size()) != 0) {
        std::cerr << "Failed to send authentication request: "
            << pcap_geterr(handle_) << std::endl;
        return -1;
    }

    return 0;
}


std::vector<uint8_t> WifiRTT::ConvertBSSIDStringToBytes(const std::string& bssid) {
    std::vector<uint8_t> bytes;
    std::stringstream ss(bssid);
    std::string item;

    while (std::getline(ss, item, ':')) {
        bytes.push_back(static_cast<uint8_t>(std::stoi(item, nullptr, 16)));
    }

    return bytes;
}

