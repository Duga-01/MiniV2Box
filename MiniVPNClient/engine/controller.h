#ifndef MINIVPNCLIENT_CONTROLLER_H
#define MINIVPNCLIENT_CONTROLLER_H

#endif //MINIVPNCLIENT_CONTROLLER_H

// controller.hpp
#pragma once
#include "mesh_runner.h"
#include "singbox_runner.h"
#include <chrono>

class MiniVPNController {
public:
    MiniVPNController(std::string singboxExe,
                      std::filesystem::path runDir,
                      std::string pythonExe,
                      std::string meshScript,
                      std::string meshWork)
        : sb_(std::move(singboxExe), std::move(runDir)),
          mesh_(std::move(pythonExe), std::move(meshScript), std::move(meshWork)) {}

    bool connect(Profile p,
                 const std::string& stunCSV,
                 const std::string& signalURL,
                 std::function<void(const std::string&)> logSink) {
        // mesh по запросу
        int m1 = 28080, m2 = 28081;
        if (p.use_mesh) {
            if (!mesh_.start(stunCSV, signalURL, m1, logSink)) return false;
            // опционально дождаться ready (не блокируя UI)
            for (int i=0;i<80 && !mesh_.ready();++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return sb_.startWithProfile(p, m1, m2, logSink);
    }

    bool reload(Profile p,
                std::function<void(const std::string&)> logSink) {
        int m1 = mesh_.ready()? mesh_.port() : 28080;
        int m2 = (m1==28080? 28081 : m1+1);
        return sb_.reloadProfile(p, m1, m2, logSink);
    }

    void disconnect() {
        sb_.stop();
        mesh_.stop();
    }

private:
    SingBoxRunner sb_;
    MeshRunner mesh_;
};
