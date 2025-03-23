#include <array>
#include <ios>
#include <iostream>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <regex>
#include <string>

#define REGISTER_COUNT 4

//################################## register ###########################################
//! VM register state
class RegisterState {
public:
    RegisterState() {
        std::fill(m_registers.begin(), m_registers.end(), 0);
    }

    // !!! Signed integer: provide negative index
    void set(int index, uint64_t value) {
        
        // VULNERABLE: we can use an arbitrary negative index to override stuff
        if (index >= REGISTER_COUNT)
            abort();
        // negative index, override a vtable pointer
        m_registers[index] = value;
    }

    // we could also read negative index, to e.g. leak a libc pointer
    uint64_t get(int index) {
        if (index >= REGISTER_COUNT)
            abort();
        return m_registers[index];
    }

private:
    std::array<uint64_t, REGISTER_COUNT> m_registers;
};
//#############################################################################


//! An instruction
class Instruction {
public:
    static Instruction *decode(const std::string &assembly, size_t position);

    Instruction(size_t position) : position(position) {}
    virtual ~Instruction() {}
    virtual void execute(RegisterState &reg) = 0;

protected:
    size_t position;
};


//################################################ ADD ################################################
//! Adds src1 and src2, stores the result in dst
class Add final : public Instruction {
public:
    virtual void execute(RegisterState &reg) override {
        reg.set(dst, reg.get(src1) + reg.get(src2));
    }

private:
    int dst, src1, src2;

    Add(size_t pos, int dst, int src1, int src2) : Instruction(pos), dst(dst), src1(src1), src2(src2) {}

    friend class Instruction;
    static const std::regex REGEX;
};
const std::regex Add::REGEX { R"(add\s+r(\S+),\s*r(\S+),\s*r(\S+))", std::regex_constants::ECMAScript | std::regex_constants::icase };


//################################################ SUB ################################################
//! Subtracts src2 from src1, stores the result in dst
class Sub final : public Instruction {
public:
    virtual void execute(RegisterState &reg) override {
        reg.set(dst, reg.get(src1) - reg.get(src2));
    }

private:
    int dst, src1, src2;

    Sub(size_t pos, int dst, int src1, int src2) : Instruction(pos), dst(dst), src1(src1), src2(src2) {}

    friend class Instruction;
    static const std::regex REGEX;
};
const std::regex Sub::REGEX { R"(sub\s+r(\S+),\s*r(\S+),\s*r(\S+))", std::regex_constants::ECMAScript | std::regex_constants::icase };


//################################################ MUL ################################################
//! Multiplies src1 and src2, stores the result in dst
class Mul final : public Instruction {
public:
    virtual void execute(RegisterState &reg) override {
        reg.set(dst, reg.get(src1) * reg.get(src2));
    }

private:
    int dst, src1, src2;

    Mul(size_t pos, int dst, int src1, int src2) : Instruction(pos), dst(dst), src1(src1), src2(src2) {}

    friend class Instruction;
    static const std::regex REGEX;
};
const std::regex Mul::REGEX { R"(mul\s+r(\S+),\s*r(\S+),\s*r(\S+))", std::regex_constants::ECMAScript | std::regex_constants::icase };


//################################################ SET ################################################
//! Sets dst to value
class Set final : public Instruction {
public:
    virtual void execute(RegisterState &reg) override {
        reg.set(dst, value);
    }

private:
    int dst, value;

    Set(size_t pos, int dst, int value) : Instruction(pos), dst(dst), value(value) {}

    friend class Instruction;
    static const std::regex REGEX;
};
const std::regex Set::REGEX { R"(set\s+r(\S+),\s*(\S+))", std::regex_constants::ECMAScript | std::regex_constants::icase };


//################################################ DUMP ################################################
//! Dumps the current register state
class Dump final : public Instruction {
public:
    virtual void execute(RegisterState &reg) override {
        std::cout << "Register dump at instruction " << position << std::endl;
        for (size_t i = 0; i < REGISTER_COUNT; ++i)
            std::cout << "  r" << std::dec << i << ": " << std::hex << std::showbase << reg.get(i) << std::endl;
    }

private:
    using Instruction::Instruction;
    friend class Instruction;
    static const std::regex REGEX;
};
const std::regex Dump::REGEX { R"(dump)", std::regex_constants::ECMAScript | std::regex_constants::icase };


//################################################ SWI ################################################
//! Performs a "software interrupt" with the command in src and the result stored in dst
class Swi final : public Instruction {
public:
    virtual void execute(RegisterState &reg) override {
        auto cmd = reg.get(src);

        std::array<char, sizeof(cmd) + 1> bytes = {};
        memcpy(bytes.data(), &cmd, sizeof(cmd));

        reg.set(dst, system(bytes.data()));
    }

private:
    int dst, src;

    Swi(size_t pos, int dst, int src) : Instruction(pos), dst(dst), src(src) {}

    friend class Instruction;
    static const std::regex REGEX;
};
const std::regex Swi::REGEX { R"(swi\s+r(\S+),\s*r(\S+))", std::regex_constants::ECMAScript | std::regex_constants::icase };
//################################################################################################


// DECODE instruction, this is called on each line we input in terminal
// assembly is our input string
// position goes from 1, 2, ...
//! Decode an instruction. Returns nullptr on invalid assembly.
Instruction *Instruction::decode(const std::string &assembly, size_t position)
{
    // we check which instruction we have via regex and return the instruction
    // There are 6 different ones: Add, Sub, Mul, Set, Dump, Swi
    // Swi is later forbidden, so probably we need to override vtable pointer of another instruction using instructions, sothat we can "change" an instruction to Swi

    std::smatch match;
    if (std::regex_match(assembly, match, Add::REGEX)) {
        int dst = std::stoi(match[1].str(), nullptr, 0);
        int src1 = std::stoi(match[2].str(), nullptr, 0);
        int src2 = std::stoi(match[3].str(), nullptr, 0);
        return new Add { position, dst, src1, src2 };
    }
    if (std::regex_match(assembly, match, Sub::REGEX)) {
        int dst = std::stoi(match[1].str(), nullptr, 0);
        int src1 = std::stoi(match[2].str(), nullptr, 0);
        int src2 = std::stoi(match[3].str(), nullptr, 0);
        return new Sub { position, dst, src1, src2 };
    }
    if (std::regex_match(assembly, match, Mul::REGEX)) {
        int dst = std::stoi(match[1].str(), nullptr, 0);
        int src1 = std::stoi(match[2].str(), nullptr, 0);
        int src2 = std::stoi(match[3].str(), nullptr, 0);
        return new Mul { position, dst, src1, src2 };
    }
    if (std::regex_match(assembly, match, Set::REGEX)) {
        int dst = std::stoi(match[1].str(), nullptr, 0);
        int value = std::stoi(match[2].str(), nullptr, 0);
        return new Set { position, dst, value };
    }
    if (std::regex_match(assembly, match, Dump::REGEX)) {
        return new Dump { position };
    }
    if (std::regex_match(assembly, match, Swi::REGEX)) {
        int dst = std::stoi(match[1].str());
        int src = std::stoi(match[2].str());
        return new Swi { position, dst, src };
    }
    return nullptr;
}


int main(void) {
    std::cout << std::unitbuf;
    std::cin >> std::unitbuf;

    std::vector<Instruction *> insns;
    std::string line;
    size_t position = 0;
    
    // A) read instructions
    while (true) {
        // 1) we read a line
        if (!std::getline(std::cin, line))
            break;
        if (line.empty())
            break;

        // 2) we docode the our input line as an instruction at pos 1, 2, ...
        auto insn = Instruction::decode(line, ++position);
        if (!insn) {
            std::cout << "`" << line << "` (line " << std::dec << position << ") is not a valid instruction" << std::endl;
            return EXIT_FAILURE;
        }

        // 3) we store the instruction in vector (array)
        insns.push_back(insn);
    }

    // B) make sure none of the instructions is a Swi instruction
    for (auto insn: insns) {
        if (auto swi = dynamic_cast<Swi *>(insn); swi) {
            std::cout << "`swi` is disabled for security reasons" << std::endl;
            return EXIT_FAILURE;
        }
    }

    // C) execute all instructions, one after another
    auto reg = new RegisterState {};
    for (auto insn: insns)
        insn->execute(*reg);
    std::cout << "Done." << std::endl;
    delete reg;

    for (auto insn: insns)
        delete insn;
}
