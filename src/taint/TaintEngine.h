#ifndef TAINT_TAINTENGINE_H
#define TAINT_TAINTENGINE_H

#include "TraceParser.h"
#include <set>
#include <string>
#include <vector>

enum class TrackMode {
    FORWARD,
    BACKWARD
};

struct TaintSource {
    RegId reg = REG_INVALID;
    uint64_t mem_addr = 0;
    bool is_mem = false;
};

class TaintEngine {
public:
    void set_mode(TrackMode mode) { mode_ = mode; }
    void set_source(const TaintSource& source);
    void run(const std::vector<TraceLine>& lines, int start_index);
    bool write_result(const std::string& output_path, const TraceParser& parser) const;

private:
    TrackMode mode_ = TrackMode::FORWARD;
    TaintSource source_;

    // 位图：快速的寄存器污点集合（覆盖所有 RegId）
    bool reg_taint_[256] = {};
    int tainted_reg_count_ = 0;
    std::set<uint64_t> tainted_mem_;

    struct ResultEntry {
        int index;          // 在 lines 数组中的索引
        // 快照
        bool reg_snapshot[256];
        std::set<uint64_t> mem_snapshot;
    };
    std::vector<ResultEntry> results_;

    // 污点操作（内联，零开销）
    inline void taint_reg(RegId id) {
        if (id == REG_INVALID || id == REG_XZR) return;
        auto nid = TraceParser::normalize(id);
        if (!reg_taint_[nid]) { reg_taint_[nid] = true; tainted_reg_count_++; }
    }
    inline void untaint_reg(RegId id) {
        if (id == REG_INVALID || id == REG_XZR) return;
        auto nid = TraceParser::normalize(id);
        if (reg_taint_[nid]) { reg_taint_[nid] = false; tainted_reg_count_--; }
    }
    inline bool is_reg_tainted(RegId id) const {
        if (id == REG_INVALID || id == REG_XZR) return false;
        return reg_taint_[TraceParser::normalize(id)];
    }

    bool any_src_tainted(const TraceLine& line) const;
    bool any_dst_tainted(const TraceLine& line) const;

    void propagate_forward(const TraceLine& line);
    void propagate_backward(const TraceLine& line);

    void record(int index);
    int count_tainted_regs() const;
};

#endif // TAINT_TAINTENGINE_H
