use std::io::Read;
use std::fmt;

pub use xml_sax::name::OwnedName;
pub use xml_sax::attribute::OwnedAttribute;
pub use xml_sax::namespace::Namespace;

use xml_sax::reader::{EventReader, XmlEvent, Error};

/// Struct representing a single XML element with its attributes and
/// children
pub struct Element {
    name: OwnedName,
    attributes: Vec<OwnedAttribute>,
    namespace: Namespace,
    children: Vec<Element>,
}

impl Element {
    /// Return the child element named `name` or `None` if it doesn't
    /// exist.
    pub fn child(&self, name: &str) -> Option<&Element> {
        for c in &self.children {
            if c.name.local_name == name {
                return Some(c);
            }
        }

        None
    }

    /// Return the attribute named `name` or `None` if it doesn't
    /// exist.
    pub fn attribute(&self, name: &str) -> Option<&OwnedAttribute> {
        self.attributes.iter().find(|a| a.name.local_name == name)
    }
}

/// DOM-style XML parser
pub struct Dom {
    root: Element,
}

impl fmt::Debug for Element {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        print_recursive(f, "", self)
    }
}

fn print_recursive(f: &mut fmt::Formatter,
                   indent: &str,
                   element: &Element) -> fmt::Result {
    try!(writeln!(f, "{}Name: {}", indent, element.name));
    try!(writeln!(f, "{}Namespace: {:?}", indent, element.namespace));

    for a in &element.attributes {
        try!(writeln!(f, "{}{:?}", indent, a));
    }

    let indent = indent.to_owned() + "  ";

    for c in &element.children {
        try!(print_recursive(f, &indent, c));
    }

    Ok(())
}

impl Dom {
    /// Parse the XML file in `reader`
    pub fn parse<R: Read>(reader: R) -> Result<Dom, Error> {
        let parser = EventReader::new(reader);

        let root = try!(Dom::do_parse(parser));

        Ok(Dom {
            root: root,
        })
    }

    fn do_parse<R: Read>(parser: EventReader<R>) -> Result<Element, Error> {
        let root = Element {
            name: OwnedName {
                local_name: "[root]".to_owned(),
                namespace: None,
                prefix: None,
            },
            attributes: Vec::new(),
            namespace: Namespace::empty(),
            children: Vec::new(),
        };

        let mut element_stack = vec![root];

        for e in parser {
            let e = try!(e);

            match e {
                XmlEvent::StartElement { name, attributes, namespace } => {
                    let child = Element {
                        name: name,
                        attributes: attributes,
                        namespace: namespace,
                        children: Vec::new(),
                    };

                    element_stack.push(child);
                }
                XmlEvent::EndElement { name } => {
                    let elem = element_stack.pop().unwrap();

                    // This shouldn't happen as the XML parser should
                    // raise an error in this situation.
                    assert!(name == elem.name);

                    let parent = element_stack.last_mut().unwrap();

                    parent.children.push(elem);
                }
                _ => (),
            }
        }

        // We should only be left with the root node
        assert!(element_stack.len() == 1);

        Ok(element_stack.pop().unwrap())
    }

    /// Get the element at `path` or `None` if the path leads nowhere.
    pub fn element(&self, path: &[&str]) -> Option<&Element> {
        let mut cur = &self.root;

        for p in path {
            match cur.child(p) {
                Some(c) => cur = c,
                None => return None,
            }
        }

        Some(cur)
    }
}

impl fmt::Debug for Dom {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.root)
    }
}
