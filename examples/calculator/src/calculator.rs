const MAX_INPUT_DIGITS: usize = 14;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Operator {
    Add,
    Subtract,
    Multiply,
    Divide,
}

impl Operator {
    fn from_key(key: &str) -> Option<Self> {
        match key {
            "+" => Some(Self::Add),
            "-" | "−" => Some(Self::Subtract),
            "*" | "×" => Some(Self::Multiply),
            "/" | "÷" => Some(Self::Divide),
            _ => None,
        }
    }

    const fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Subtract => "−",
            Self::Multiply => "×",
            Self::Divide => "÷",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Calculator {
    display: String,
    history: String,
    stored_value: Option<f64>,
    pending_operator: Option<Operator>,
    repeat_operation: Option<(Operator, f64)>,
    input_fresh: bool,
    has_error: bool,
}

impl Default for Calculator {
    fn default() -> Self {
        Self {
            display: "0".to_owned(),
            history: String::new(),
            stored_value: None,
            pending_operator: None,
            repeat_operation: None,
            input_fresh: true,
            has_error: false,
        }
    }
}

impl Calculator {
    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    pub(crate) fn history(&self) -> &str {
        &self.history
    }

    pub(crate) fn active_operator(&self) -> &'static str {
        self.pending_operator.map_or("", Operator::symbol)
    }

    pub(crate) fn press(&mut self, key: &str) {
        match key {
            "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" => {
                self.input_digit(key.as_bytes()[0] as char);
            }
            "." => self.input_decimal(),
            "AC" | "C" => self.clear(),
            "⌫" => self.backspace(),
            "±" => self.toggle_sign(),
            "%" => self.percent(),
            "=" => self.equals(),
            _ => {
                if let Some(operator) = Operator::from_key(key) {
                    self.select_operator(operator);
                }
            }
        }
    }

    fn input_digit(&mut self, digit: char) {
        self.recover_for_input();
        if self.input_fresh {
            self.begin_new_input();
            self.display.clear();
            self.input_fresh = false;
        }

        if self.display.chars().filter(char::is_ascii_digit).count() >= MAX_INPUT_DIGITS {
            return;
        }
        match self.display.as_str() {
            "0" if digit != '0' => self.display = digit.to_string(),
            "-0" if digit != '0' => self.display = format!("-{digit}"),
            "0" | "-0" => {}
            _ => self.display.push(digit),
        }
    }

    fn input_decimal(&mut self) {
        self.recover_for_input();
        if self.input_fresh {
            self.begin_new_input();
            self.display = "0.".to_owned();
            self.input_fresh = false;
        } else if !self.display.contains(['.', 'e']) {
            self.display.push('.');
        }
    }

    fn clear(&mut self) {
        *self = Self::default();
    }

    fn backspace(&mut self) {
        if self.has_error {
            self.clear();
            return;
        }
        if self.input_fresh {
            if self.pending_operator.is_none() {
                self.clear();
            } else {
                self.display = "0".to_owned();
                self.input_fresh = false;
            }
            return;
        }
        self.display.pop();
        if self.display.is_empty() || self.display == "-" {
            self.display = "0".to_owned();
        }
    }

    fn toggle_sign(&mut self) {
        self.recover_for_input();
        if self.input_fresh {
            self.begin_new_input();
            self.input_fresh = false;
        }
        if let Some(unsigned) = self.display.strip_prefix('-') {
            self.display = unsigned.to_owned();
        } else {
            self.display.insert(0, '-');
        }
    }

    fn percent(&mut self) {
        if self.has_error {
            return;
        }
        let Some(value) = self.current_value() else {
            self.fail("Invalid number");
            return;
        };
        self.display = format_number(value / 100.0);
        self.input_fresh = true;
        if self.pending_operator.is_none() {
            self.stored_value = None;
            self.repeat_operation = None;
            self.history.clear();
        }
    }

    fn select_operator(&mut self, operator: Operator) {
        if self.has_error {
            return;
        }
        let Some(current) = self.current_value() else {
            self.fail("Invalid number");
            return;
        };

        if let Some(pending) = self.pending_operator {
            if !self.input_fresh {
                let left = self.stored_value.unwrap_or(current);
                let Some(result) = self.calculate(left, pending, current) else {
                    return;
                };
                self.display = format_number(result);
                self.stored_value = Some(result);
            }
        } else {
            self.stored_value = Some(current);
        }

        self.pending_operator = Some(operator);
        self.repeat_operation = None;
        self.history = format!("{} {}", self.display, operator.symbol());
        self.input_fresh = true;
    }

    fn equals(&mut self) {
        if self.has_error {
            return;
        }
        let Some(current) = self.current_value() else {
            self.fail("Invalid number");
            return;
        };

        let operation = if let Some(operator) = self.pending_operator.take() {
            Some((self.stored_value.unwrap_or(current), operator, current))
        } else {
            self.repeat_operation
                .map(|(operator, right)| (current, operator, right))
        };
        let Some((left, operator, right)) = operation else {
            return;
        };
        let Some(result) = self.calculate(left, operator, right) else {
            return;
        };

        self.history = format!(
            "{} {} {} =",
            format_number(left),
            operator.symbol(),
            format_number(right)
        );
        self.display = format_number(result);
        self.stored_value = Some(result);
        self.repeat_operation = Some((operator, right));
        self.input_fresh = true;
    }

    fn calculate(&mut self, left: f64, operator: Operator, right: f64) -> Option<f64> {
        if operator == Operator::Divide && right == 0.0 {
            self.fail("Cannot divide by zero");
            return None;
        }
        let result = match operator {
            Operator::Add => left + right,
            Operator::Subtract => left - right,
            Operator::Multiply => left * right,
            Operator::Divide => left / right,
        };
        if result.is_finite() {
            Some(result)
        } else {
            self.fail("Result is too large");
            None
        }
    }

    fn current_value(&self) -> Option<f64> {
        self.display
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
    }

    fn recover_for_input(&mut self) {
        if self.has_error {
            self.clear();
        }
    }

    fn begin_new_input(&mut self) {
        if self.pending_operator.is_none() {
            self.stored_value = None;
            self.repeat_operation = None;
            self.history.clear();
        }
    }

    fn fail(&mut self, message: &str) {
        self.display = "Error".to_owned();
        self.history = message.to_owned();
        self.stored_value = None;
        self.pending_operator = None;
        self.repeat_operation = None;
        self.input_fresh = true;
        self.has_error = true;
    }
}

fn format_number(value: f64) -> String {
    let value = if value.abs() < 1e-12 { 0.0 } else { value };
    let absolute = value.abs();
    let mut text = if absolute != 0.0 && !(1e-9..1e12).contains(&absolute) {
        format!("{value:.8e}")
    } else {
        format!("{value:.10}")
    };
    let exponent = text.find('e').map(|index| text.split_off(index));
    while text.ends_with('0') && text.contains('.') {
        text.pop();
    }
    if text.ends_with('.') {
        text.pop();
    }
    if let Some(exponent) = exponent {
        text.push_str(&exponent);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::Calculator;

    fn press(calculator: &mut Calculator, keys: &[&str]) {
        for key in keys {
            calculator.press(key);
        }
    }

    #[test]
    fn decimal_addition_produces_a_clean_display() {
        let mut calculator = Calculator::default();
        press(
            &mut calculator,
            &["1", "2", ".", "5", "+", "7", ".", "5", "="],
        );
        assert_eq!(calculator.display(), "20");
        assert_eq!(calculator.history(), "12.5 + 7.5 =");
    }

    #[test]
    fn chained_operations_follow_handheld_calculator_order() {
        let mut calculator = Calculator::default();
        press(&mut calculator, &["2", "+", "3", "×", "4", "="]);
        assert_eq!(calculator.display(), "20");
    }

    #[test]
    fn equals_repeats_the_last_operation() {
        let mut calculator = Calculator::default();
        press(&mut calculator, &["5", "+", "2", "=", "="]);
        assert_eq!(calculator.display(), "9");
        assert_eq!(calculator.history(), "7 + 2 =");
    }

    #[test]
    fn a_second_operator_replaces_the_pending_operator() {
        let mut calculator = Calculator::default();
        press(&mut calculator, &["8", "+", "−", "2", "="]);
        assert_eq!(calculator.display(), "6");
    }

    #[test]
    fn division_by_zero_reports_an_error_and_digit_input_recovers() {
        let mut calculator = Calculator::default();
        press(&mut calculator, &["9", "÷", "0", "="]);
        assert_eq!(calculator.display(), "Error");
        assert_eq!(calculator.history(), "Cannot divide by zero");

        calculator.press("4");
        assert_eq!(calculator.display(), "4");
        assert_eq!(calculator.history(), "");
    }

    #[test]
    fn editing_sign_and_percent_are_deterministic() {
        let mut calculator = Calculator::default();
        press(&mut calculator, &["1", "2", "3", "⌫", "±", "%"]);
        assert_eq!(calculator.display(), "-0.12");
        calculator.press("AC");
        assert_eq!(calculator.display(), "0");
    }
}
