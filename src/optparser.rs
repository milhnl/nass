pub struct OptParser<T: Iterator<Item = String>> {
    optind: usize,
    args: std::iter::Peekable<T>,
}

#[derive(Debug)]
pub enum Argument {
    Long(String),
    Short(char),
}

impl<T: Iterator<Item = String>> OptParser<T> {
    pub fn new(args: T) -> Self {
        OptParser::<T> {
            optind: 0,
            args: args.peekable(),
        }
    }
    pub fn next_opt(&mut self) -> Option<Argument> {
        let cur = self.args.peek()?;
        if cur.starts_with("--") {
            let mut cur = self.args.next().unwrap();
            cur.drain(..2);
            self.optind = 0;
            if cur.is_empty() {
                None
            } else {
                Some(Argument::Long(cur))
            }
        } else if cur.starts_with('-') && cur.len() > 1 {
            self.optind += 1;
            let mut chars = cur.chars();
            let next = chars.nth(self.optind).unwrap();
            if chars.count() == 0 {
                self.args.next();
                self.optind = 0;
            }
            Some(Argument::Short(next))
        } else {
            None
        }
    }
}

impl<T> Iterator for OptParser<T>
where
    T: Iterator<Item = String>,
{
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let mut arg = self.args.next()?;
        if self.optind != 0 {
            arg.drain(..self.optind);
        }
        Some(arg)
    }
}
