/* System call argument iterator component
 *
 * iterates through each argument of the system call by finding unescaped ',' characters
 *
 */

pub struct ArgSeperator<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for ArgSeperator<'a> {
    type Item = &'a[u8];

    fn next(&mut self) -> Option<Self::Item> {

        let mut in_quotes = false;
        let mut in_arrows = false;
        let remaining = &self.input[self.pos..];

        if remaining.len() < 1 {
            return None;
        }

        for (i,&byte) in remaining.iter().enumerate(){
            // check if we have a value encased in " -> check for \ to see if the " was escaped
            // itself (then it is part of the value: e.g., " some\"string "
            if byte == b'"' && remaining[i-1] != b'\\'{
                in_quotes = !in_quotes; 
            }
            //FIXME check if filenames have , (check if they are escaped in strace output)
            if (!in_quotes && byte == b'<' && !in_arrows) || (!in_quotes && byte == b'>' && in_arrows) {
                in_arrows = !in_arrows;
            }

            if !in_quotes && !in_arrows {
                if byte == b','{ 
                    self.pos = self.pos + i + 1;
                    return Some(clean_argument(&remaining[..i+1])); 
                }
            }
            // eol check and get arg
            if i == remaining.len()-1 {
                // return final arg or everything if we found no ',' till then
                self.pos = self.pos + i + 1;
                return Some(clean_argument(&remaining[..i+1])); 
            }
        }
        return None;
    }

}

pub fn parse(input: &[u8]) -> ArgSeperator<'_>{
    ArgSeperator { input, pos:0 }
}

fn clean_argument(input: &[u8]) -> &[u8]{
    // remove the preceding whitespace (all but the first args should have this)
    // and strip whitespaces and brackets at the start and end of each argument
    let start = input.iter().position(|byte| !matches!(byte, b' ' | b'[' |  b'{' )).unwrap_or(0);
    let end = input.iter().rposition(|byte| !matches!(byte, b' ' | b']' |  b'}' | b',')).map_or(input.len(), |i| i+1);
    return &input[start..end];
}

