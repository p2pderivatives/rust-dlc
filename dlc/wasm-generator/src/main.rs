use syn::{PatType, PathArguments, Type};

fn print_type(t: &Type) {
    match t {
        syn::Type::Array(a) => {
            println!("Array");
            print_type(&a.elem);
        }
        syn::Type::Reference(r) => {
            println!("Reference");
            print_type(&r.elem);
        }
        syn::Type::Slice(s) => {
            println!("Slice");
            print_type(&s.elem);
        }
        Type::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                println!("{}", ident);
            } else if p.path.leading_colon.is_none() && p.path.segments.len() == 1 {
                let first_seg = &p.path.segments[0];
                if first_seg.ident == "Option" {
                    if let PathArguments::AngleBracketed(a) = &first_seg.arguments {
                        let ty = a.args.first().unwrap();
                        match ty {
                            syn::GenericArgument::Type(t) => print_type(t),
                            _ => panic!(),
                        }
                    }
                }
            } else {
                panic!();
            }
        }
        Type::BareFn(_) => todo!(),
        Type::Group(_) => todo!(),
        Type::ImplTrait(_) => todo!(),
        Type::Infer(_) => todo!(),
        Type::Macro(_) => todo!(),
        Type::Never(_) => todo!(),
        Type::Paren(_) => todo!(),
        Type::Ptr(_) => todo!(),
        Type::TraitObject(_) => todo!(),
        Type::Tuple(_) => todo!(),
        Type::Verbatim(_) => todo!(),
        _ => todo!(),
    }
}

fn print_pat_type(t: &PatType) {
    match t.pat.as_ref() {
        syn::Pat::Ident(i) => println!("{}", i.ident),
        _ => panic!(),
    };
    print_type(&t.ty);
}

fn main() {
    let file = include_str!("../../src/lib.rs");
    let ast = syn::parse_file(&file).unwrap();

    for item in ast.items {
        match item {
            syn::Item::Fn(f) => {
                println!("{}", f.sig.ident.to_string());
                for i in f.sig.inputs {
                    match i {
                        syn::FnArg::Receiver(_) => panic!(),
                        syn::FnArg::Typed(t) => {
                            print_pat_type(&t);
                        }
                    };
                }
            }
            _ => {}
        };
    }
}
