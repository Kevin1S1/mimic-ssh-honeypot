use super::env::Env;

const MAX_DEPTH: u32 = 32;

pub fn eval(env: &Env, expr: &str) -> Option<i64> {
    let tokens = tokenize(expr)?;
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
        depth: 0,
        env,
    };
    let value = parser.comparison()?;

    if parser.pos == tokens.len() {
        Some(value)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Num(i64),

    Name(String),

    Op(&'static str),
}

fn tokenize(expr: &str) -> Option<Vec<Token>> {
    let chars: Vec<char> = expr.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_alphanumeric() {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            let value = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                Some(hex) => i64::from_str_radix(hex, 16).ok()?,
                None => text.parse().ok()?,
            };
            tokens.push(Token::Num(value));
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            tokens.push(Token::Name(chars[start..i].iter().collect()));
            continue;
        }

        let pair: String = chars[i..chars.len().min(i + 2)].iter().collect();
        let two = match pair.as_str() {
            "==" => Some("=="),
            "!=" => Some("!="),
            "<=" => Some("<="),
            ">=" => Some(">="),
            _ => None,
        };
        if let Some(op) = two {
            tokens.push(Token::Op(op));
            i += 2;
            continue;
        }
        let one = match c {
            '+' => "+",
            '-' => "-",
            '*' => "*",
            '/' => "/",
            '%' => "%",
            '(' => "(",
            ')' => ")",
            '<' => "<",
            '>' => ">",
            _ => return None,
        };
        tokens.push(Token::Op(one));
        i += 1;
    }
    Some(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    depth: u32,
    env: &'a Env,
}

impl Parser<'_> {
    fn eat(&mut self, op: &'static str) -> bool {
        if self.tokens.get(self.pos) == Some(&Token::Op(op)) {
            self.pos += 1;
            return true;
        }
        false
    }

    fn eat_any(&mut self, ops: &[&'static str]) -> Option<&'static str> {
        let &Token::Op(op) = self.tokens.get(self.pos)? else {
            return None;
        };
        if ops.contains(&op) {
            self.pos += 1;
            return Some(op);
        }
        None
    }

    fn comparison(&mut self) -> Option<i64> {
        let mut left = self.additive()?;
        while let Some(op) = self.eat_any(&["==", "!=", "<=", ">=", "<", ">"]) {
            let right = self.additive()?;
            let truth = match op {
                "==" => left == right,
                "!=" => left != right,
                "<=" => left <= right,
                ">=" => left >= right,
                "<" => left < right,
                _ => left > right,
            };
            left = i64::from(truth);
        }
        Some(left)
    }

    fn additive(&mut self) -> Option<i64> {
        let mut left = self.multiplicative()?;
        while let Some(op) = self.eat_any(&["+", "-"]) {
            let right = self.multiplicative()?;
            left = if op == "+" {
                left.wrapping_add(right)
            } else {
                left.wrapping_sub(right)
            };
        }
        Some(left)
    }

    fn multiplicative(&mut self) -> Option<i64> {
        let mut left = self.unary()?;
        while let Some(op) = self.eat_any(&["*", "/", "%"]) {
            let right = self.unary()?;
            left = match op {
                "*" => left.wrapping_mul(right),

                "/" => left.checked_div(right)?,
                _ => left.checked_rem(right)?,
            };
        }
        Some(left)
    }

    fn unary(&mut self) -> Option<i64> {
        if self.eat("-") {
            return Some(self.unary()?.wrapping_neg());
        }
        if self.eat("+") {
            return self.unary();
        }
        self.primary()
    }

    fn primary(&mut self) -> Option<i64> {
        if self.eat("(") {
            if self.depth >= MAX_DEPTH {
                return None;
            }
            self.depth += 1;
            let value = self.comparison();
            self.depth -= 1;
            let value = value?;
            return self.eat(")").then_some(value);
        }
        let token = self.tokens.get(self.pos)?.clone();
        self.pos += 1;
        match token {
            Token::Num(value) => Some(value),

            Token::Name(name) => Some(
                self.env
                    .get(&name)
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0),
            ),
            Token::Op(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        Env::login("root", "/root", "debian")
    }

    #[test]
    fn precedence_and_parentheses() {
        let env = env();
        assert_eq!(eval(&env, "2+3*4"), Some(14));
        assert_eq!(eval(&env, "(2+3)*4"), Some(20));
        assert_eq!(eval(&env, " 10 / 3 "), Some(3));
        assert_eq!(eval(&env, "10 % 3"), Some(1));
        assert_eq!(eval(&env, "-5 + 2"), Some(-3));
        assert_eq!(eval(&env, "0x10 + 1"), Some(17));
    }

    #[test]
    fn comparisons_yield_one_or_zero() {
        let env = env();
        assert_eq!(eval(&env, "3 > 2"), Some(1));
        assert_eq!(eval(&env, "3 == 2"), Some(0));
        assert_eq!(eval(&env, "2 <= 2"), Some(1));
    }

    #[test]
    fn names_resolve_and_default_to_zero() {
        let mut env = env();
        env.set("N", "41");
        env.set("WORD", "abc");
        assert_eq!(eval(&env, "N + 1"), Some(42));
        assert_eq!(eval(&env, "WORD + 1"), Some(1));
        assert_eq!(eval(&env, "NOPE + 7"), Some(7));
    }

    #[test]
    fn malformed_expressions_and_division_by_zero_fail() {
        let env = env();
        assert_eq!(eval(&env, "1 +"), None);
        assert_eq!(eval(&env, "1 2"), None);
        assert_eq!(eval(&env, "(1"), None);
        assert_eq!(eval(&env, "1 / 0"), None);
        assert_eq!(eval(&env, "1 % 0"), None);
        assert_eq!(eval(&env, "a $ b"), None);
    }

    #[test]
    fn overflow_wraps_instead_of_panicking() {
        let env = env();
        assert_eq!(eval(&env, "9223372036854775807 + 1"), Some(i64::MIN));
        assert_eq!(eval(&env, "-9223372036854775807 - 2"), Some(i64::MAX));
    }

    #[test]
    fn deeply_nested_parentheses_are_refused() {
        let env = env();
        let expr = format!("{}1{}", "(".repeat(64), ")".repeat(64));
        assert_eq!(eval(&env, &expr), None);
    }
}
