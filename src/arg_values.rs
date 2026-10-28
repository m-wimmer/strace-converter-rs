
// enum for arguments. if a key is found more than once we swap to many and just append. serde then
// serializes into an array. easy
#[derive(Debug)]
#[derive(Clone)]
#[derive(serde::Serialize)]
#[derive(PartialEq)]
#[serde(untagged)]
pub enum ArgValue<'a> {
    One(&'a str),
    Many(Vec<&'a str>)
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum OwnedArgValue {
    One(String),
    Many(Vec<String>)
}

