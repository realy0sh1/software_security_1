#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <iostream>
#include <list>
#include <ostream>
#include <string>
#include <typeinfo>

#include <cxxabi.h>

#if !defined(NO_WIN_FUNCTION)
void win() { system("cat /flag"); }
static bool __initialized = [] {
    std::cout << "win() is at 0x" << std::hex << (unsigned long) win << std::dec << std::endl;
    return true;
} ();
#endif

// No free() means this is safe, right?
void operator delete(void *) noexcept {}
void operator delete(void *, std::size_t) noexcept {}
void operator delete[](void *) noexcept {}
void operator delete[](void *, std::size_t) noexcept {}

class Expr {
protected:
    virtual std::ostream &print(std::ostream &stream) const = 0;

public:
    Expr() = default;
    Expr(const Expr &) = delete;
    Expr(Expr &&) = default;
    Expr &operator=(const Expr &) = delete;
    Expr &operator=(Expr &&) = default;
    virtual ~Expr() = default;

    virtual const char *name() const = 0;
    virtual double evaluate() const = 0;
    virtual void dump() const { int _; std::cout << "<" << reinterpret_cast<const void*>(this) << ": " << abi::__cxa_demangle(typeid(*this).name(), nullptr, nullptr, &_) << ">"; }

    friend std::ostream &operator<<(std::ostream &stream, const Expr &expr) { return expr.print(stream); }
};

class Number final : public Expr {
protected:
    double m_value;
    virtual std::ostream &print(std::ostream &stream) const override { return stream << m_value; }
    virtual const char *name() const override { return "Number"; }

public:
    explicit Number(double value) : m_value(value) {}
    virtual double evaluate() const override { return m_value; }
};

class Comment : public Expr {
protected:
    // this points to a string of our choice via: //string_of_our_choice (we could creaet a fake vtable and have a pointer to it on the stack :)
    const char *m_data;
    virtual std::ostream &print(std::ostream &stream) const override { return stream << m_data; }
    virtual const char *name() const override { return "Comment"; }

public:
    // constructor 
    explicit Comment(const char *data) : m_data(data) {}
    virtual double evaluate() const override { return NAN; }
    virtual void dump() const override { Expr::dump(); std::cout << "(" << reinterpret_cast<const void *>(m_data) << ")"; }
};

class BinaryExpr : public Expr {
protected:
    Expr *m_lhs;
    Expr *m_rhs;
    virtual std::ostream &print(std::ostream &stream) const override { return stream << name() << "(" << *m_lhs << ", " << *m_rhs << ")"; }
    virtual void dump() const override { Expr::dump(); std::cout << "("; m_lhs->dump(); std::cout << ", "; m_rhs->dump(); std::cout << ")"; }

public:
    explicit BinaryExpr(Expr *lhs, Expr *rhs) : m_lhs(lhs), m_rhs(rhs) {}
    // virtual ~BinaryExpr() override { delete m_lhs; delete m_rhs; } // Ownership here is broken anyways, might as well not delete anything
};

struct InlineOp : public BinaryExpr {
    using BinaryExpr::BinaryExpr;
protected:
    virtual std::ostream &print(std::ostream &stream) const override { return stream << "(" << *m_lhs << " " << name() << " " << *m_rhs << ")"; }
};

class UnaryExpr : public Expr {
protected:
    Expr *m_arg;
    virtual std::ostream &print(std::ostream &stream) const override { return stream << name() << "(" << *m_arg << ")"; }
    virtual void dump() const override { Expr::dump(); std::cout << "("; m_arg->dump(); std::cout << ")"; }

public:
    explicit UnaryExpr(Expr *arg) : m_arg(arg) {}
    // virtual ~UnaryExpr() override { delete m_arg; } // Ownership here is broken anyways, might as well not delete anything
};

#define MAKE_INLINE_OP(ClassName, Op) \
    struct ClassName final : public InlineOp { \
        using InlineOp::InlineOp; \
        virtual const char *name() const override { return #Op; } \
        virtual double evaluate() const override { return m_lhs->evaluate() Op m_rhs->evaluate(); } \
    }
#define MAKE_BINARY_EXPR(ClassName, Name, Fn) \
    struct ClassName final : public BinaryExpr { \
        using BinaryExpr::BinaryExpr; \
        virtual const char *name() const override { return Name; } \
        virtual double evaluate() const override { return Fn(m_lhs->evaluate(), m_rhs->evaluate()); } \
    }
#define MAKE_UNARY_EXPR(ClassName, Name, Fn) \
    struct ClassName final : public UnaryExpr { \
        using UnaryExpr::UnaryExpr; \
        virtual const char *name() const override { return Name; } \
        virtual double evaluate() const override { return Fn(m_arg->evaluate()); } \
    }

MAKE_INLINE_OP(Addition, +);
MAKE_INLINE_OP(Subtraction, -);
MAKE_INLINE_OP(Multiplication, *);
MAKE_INLINE_OP(Division, /);

MAKE_BINARY_EXPR(Max, "max", fmax);
MAKE_BINARY_EXPR(Min, "min", fmin);
MAKE_BINARY_EXPR(Pow, "pow", pow);

MAKE_UNARY_EXPR(Negation, "-", -);
MAKE_UNARY_EXPR(Abs, "abs", fabs);
MAKE_UNARY_EXPR(Sqrt, "sqrt", sqrt);
MAKE_UNARY_EXPR(Sin, "sin", sin);
MAKE_UNARY_EXPR(Cos, "cos", cos);
MAKE_UNARY_EXPR(Tan, "tan", tan);
MAKE_UNARY_EXPR(Ln, "ln", log);

namespace {
    std::string_view trim(std::string_view view) {
        while (view.starts_with(" ") || view.starts_with("\n")) { view.remove_prefix(1); }
        while (view.ends_with(" ") || view.ends_with("\n")) { view.remove_suffix(1); }
        return view;
    }
}

class Calculator {
    struct NamedExpr {
        char raw_name[16];
        Expr *expr;

        NamedExpr(std::string_view name, Expr *expr) : expr(expr) { set_name(name); }

        // FOUND OVERFLOW: 

        // we can change the name (first 16 chars) and then override the pointer to the expr
        // thus we can do Comment + 8 sothat the comment gets interpreted as a vtable
        // TODO: leak (stack address) of Comment
        void set_name(std::string_view name) {
            std::memset(this->raw_name, 0, sizeof(this->raw_name));
            std::memcpy(this->raw_name, name.data(), name.length());
        }

        std::string_view name() const { return raw_name; }
    };

    // list of NamedExpr that are saved
    std::list<NamedExpr> m_exprs;

    Expr *parse_value(std::string_view part, bool may_be_expr = true) {
        part = trim(part);

        double value;
        auto result = std::from_chars(part.begin(), part.end(), value);
        if (result.ec != std::errc::invalid_argument && result.ec != std::errc::result_out_of_range && result.ptr == part.end())
            return new Number(value);
        return may_be_expr ? find_expr(part) : nullptr;
    }

    std::pair<Expr *, Expr *> parse_binary_expr(std::string_view part, std::string_view separator) {
        part = trim(part);
        if (auto pos = part.find(separator); pos != std::string_view::npos)
            return { parse_value(part.substr(0, pos)), parse_value(part.substr(pos + separator.size())) };
        return { nullptr, nullptr };
    }

public:
    Expr *parse_expr(std::string_view line) {
        line = trim(line);
        if (line.starts_with("max(") && line.ends_with(")"))
            if (auto [lhs, rhs] = parse_binary_expr(line.substr(4, line.size() - 5), ", "); lhs && rhs)
                return new Max(lhs, rhs);
        if (line.starts_with("min(") && line.ends_with(")"))
            if (auto [lhs, rhs] = parse_binary_expr(line.substr(4, line.size() - 5), ", "); lhs && rhs)
                return new Min(lhs, rhs);
        if (line.starts_with("pow(") && line.ends_with(")"))
            if (auto [lhs, rhs] = parse_binary_expr(line.substr(4, line.size() - 5), ", "); lhs && rhs)
                return new Pow(lhs, rhs);
        if (line.starts_with("-"))
            if (auto val = parse_value(line.substr(1)); val)
                return new Negation(val);
        if (line.starts_with("abs(") && line.ends_with(")"))
            if (auto val = parse_value(line.substr(4, line.size() - 5)); val)
                return new Abs(val);
        if (line.starts_with("sqrt(") && line.ends_with(")"))
            if (auto val = parse_value(line.substr(5, line.size() - 6)); val)
                return new Sqrt(val);
        if (line.starts_with("sin(") && line.ends_with(")"))
            if (auto val = parse_value(line.substr(4, line.size() - 5)); val)
                return new Sin(val);
        if (line.starts_with("cos(") && line.ends_with(")"))
            if (auto val = parse_value(line.substr(4, line.size() - 5)); val)
                return new Cos(val);
        if (line.starts_with("tan(") && line.ends_with(")"))
            if (auto val = parse_value(line.substr(4, line.size() - 5)); val)
                return new Tan(val);
        if (line.starts_with("ln(") && line.ends_with(")"))
            if (auto val = parse_value(line.substr(3, line.size() - 4)); val)
                return new Ln(val);

        if (line.starts_with("dump(") && line.ends_with(")"))
            if (auto val = find_expr(line.substr(5, line.size() - 6)); val)
                return (std::cout << "  ", val->dump(), std::cout << std::endl, nullptr);
        if (line == "list()")
            return (std::for_each(m_exprs.begin(), m_exprs.end(), [](const NamedExpr &e) { std::cout << "  " << e.name() << std::endl; }), nullptr);

        if (line.starts_with("//"))
            if (auto data = new char[line.size() + 1])
                return (std::memcpy(data, line.data(), line.size()), data[line.size()] = 0, new Comment(data));

        if (line.find("**") != std::string_view::npos)
            if (auto [lhs, rhs] = parse_binary_expr(line, "**"); lhs && rhs)
                return new Pow(lhs, rhs);

        if (line.find("+") != std::string_view::npos)
            if (auto [lhs, rhs] = parse_binary_expr(line, "+"); lhs && rhs)
                return new Addition(lhs, rhs);
        if (line.find("-") != std::string_view::npos)
            if (auto [lhs, rhs] = parse_binary_expr(line, "-"); lhs && rhs)
                return new Subtraction(lhs, rhs);
        if (line.find("*") != std::string_view::npos)
            if (auto [lhs, rhs] = parse_binary_expr(line, "*"); lhs && rhs)
                return new Multiplication(lhs, rhs);
        if (line.find("/") != std::string_view::npos)
            if (auto [lhs, rhs] = parse_binary_expr(line, "/"); lhs && rhs)
                return new Division(lhs, rhs);

        return parse_value(line, false);
    }

    Expr *find_expr(std::string_view name) {
        name = trim(name);
        if (auto it = std::find_if(m_exprs.begin(), m_exprs.end(), [name](const NamedExpr &e) { return e.name() == name; }); it != m_exprs.end())
            return it->expr;
        return nullptr;
    }

    std::string insert_expr(Expr *expr, std::string name = "") {
        if (name.empty())
            name = "v" + std::to_string(m_exprs.size());
        if (auto it = std::find_if(m_exprs.begin(), m_exprs.end(), [name](const NamedExpr &e) { return e.name() == name; }); it != m_exprs.end())
            it->expr = expr;
        else
            m_exprs.push_front(NamedExpr(name, expr));
        return name;
    }

    bool rename_expr(std::string_view from, std::string_view to) {
        from = trim(from);
        to = trim(to);
        if (to.empty() || ('0' <= to[0] && to[0] <= '9'))
            return false; // Invalid name
        if (to.starts_with("v") && to.length() > 1) {
            auto suffix = to.substr(1);
            if (std::all_of(suffix.begin(), suffix.end(), [](char c) { return '0' <= c && c <= '9'; }))
                return false; // Reserved name
        }
        if (auto it = std::find_if(m_exprs.begin(), m_exprs.end(), [from](const NamedExpr &e) { return e.name() == from; }); it != m_exprs.end()) {
            if (auto it2 = std::find_if(m_exprs.begin(), m_exprs.end(), [to](const NamedExpr &e) { return e.name() == to; }); it2 != m_exprs.end()) {                
                // Name already exists, replace that expression
                it2->expr = it->expr;
                m_exprs.erase(it);
            } else {
                it->set_name(to);
            }
            return true;
        }
        return false;
    }
};

int main()
{
    Calculator calc;
    for (std::string line; std::getline(std::cin, line);) {
        if (auto expr = calc.parse_expr(line); expr) {
            auto name = calc.insert_expr(expr);
            std::cout << name << " := " << *expr << std::endl;
        } else if (auto expr = calc.find_expr(line); expr) {

            std::cout << trim(line) << " := " << *expr << " => " << expr->evaluate() << std::endl;
        } else if (auto pos = line.find(":="); pos != std::string::npos) {
            auto to = trim(std::string_view { line }.substr(0, pos));
            auto from = trim(std::string_view { line }.substr(pos + 2));
            
            // rename has buffer overlfow => override pointer to expression => + 0x8 sothat string is vtable

            // we could guess last byte
            
            if (calc.rename_expr(from, to))
                std::cout << to << " <- " << from << std::endl;
            else
                std::cout << "?" << std::endl;
        } else if (trim(std::string_view { line }) == "quit") {
            break;
        } else {
            std::cout << "?" << std::endl;
        }
    }
    std::_Exit(0);
}
