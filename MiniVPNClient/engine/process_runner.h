#ifndef MINIVPNCLIENT_PROCESS_RUNNER_H
#define MINIVPNCLIENT_PROCESS_RUNNER_H

#endif //MINIVPNCLIENT_PROCESS_RUNNER_H

// process_runner.hpp
#pragma once
#include <boost/process.hpp>
#include <boost/asio.hpp>
#include <functional>
#include <optional>
#include <string>
#include <thread>

class ProcessRunner {
public:
    using LogHandler = std::function<void(const std::string&)>;
    using ExitHandler = std::function<void(int)>;

    explicit ProcessRunner(std::string exe)
        : exe_(std::move(exe)), ios_(), outPipe_(ios_), errPipe_(ios_) {}

    ~ProcessRunner() { stop(); }

    bool start(const std::vector<std::string>& args,
               const std::string& workDir,
               LogHandler onStdout,
               LogHandler onStderr,
               ExitHandler onExit = nullptr) {
        if (proc_ && proc_->running()) return true;
        onStdout_ = std::move(onStdout);
        onStderr_ = std::move(onStderr);
        onExit_   = std::move(onExit);

        namespace bp = boost::process;
        try {
            proc_.emplace(
                bp::child(
                    exe_, bp::args(args),
                    bp::start_dir(workDir),
                    bp::std_out > outPipe_,
                    bp::std_err > errPipe_,
                    ios_,
                    bp::on_exit([this](int code, const std::error_code&) {
                        if (onExit_) onExit_(code);
                    })
                )
            );
            readLoop(outPipe_, onStdout_);
            readLoop(errPipe_, onStderr_);
            ioThread_ = std::thread([this]{ ios_.run(); });
            return true;
        } catch (const std::exception& ex) {
            if (onStderr_) onStderr_(std::string("start error: ") + ex.what());
            return false;
        }
    }

    void stop() {
        if (!proc_) return;
        try {
            if (proc_->running()) {
                proc_->terminate();
                proc_->wait();
            }
        } catch (...) {}
        ios_.stop();
        if (ioThread_.joinable()) ioThread_.join();
        proc_.reset();
        // сбросить контекст для последующего старта
        ios_ = boost::asio::io_context{};
        outPipe_ = boost::process::async_pipe(ios_);
        errPipe_ = boost::process::async_pipe(ios_);
    }

    bool running() const { return proc_ && proc_->running(); }

private:
    void readLoop(boost::process::async_pipe& pipe, LogHandler sink) {
        auto buf = std::make_shared<std::array<char, 4096>>();
        pipe.async_read_some(
            boost::asio::buffer(*buf),
            [this, &pipe, buf, sink](const boost::system::error_code& ec, std::size_t n) {
                if (!ec && n > 0) {
                    if (sink) sink(std::string(buf->data(), n));
                    readLoop(pipe, sink);
                } else {
                    // pipe closed or error — ничего, процесс завершится
                }
            }
        );
    }

    std::string exe_;
    std::optional<boost::process::child> proc_;
    boost::asio::io_context ios_;
    boost::process::async_pipe outPipe_{ios_};
    boost::process::async_pipe errPipe_{ios_};
    std::thread ioThread_;
    LogHandler onStdout_, onStderr_;
    ExitHandler onExit_;
};
