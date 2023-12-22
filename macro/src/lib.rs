extern crate proc_macro;
extern crate quote;
extern crate syn;

use self::proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Ident, ItemFn};

#[proc_macro_attribute]
pub fn count(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut function = parse_macro_input!(input as ItemFn);

    // Variable to store the name of the ContextWrapper<F> parameter
    let mut context_param_name: Option<&Ident> = None;

    // Iterate over the function's parameters
    for input in function.sig.inputs.iter() {
        if let syn::FnArg::Typed(pat_type) = input {
            // Debug: print the parameter's type

            if let syn::Type::Reference(type_ref) = &*pat_type.ty {
                if let syn::Type::Path(type_path) = &*type_ref.elem {
                    if type_path
                        .path
                        .segments
                        .last()
                        .map_or(false, |segment| segment.ident == "ContextWrapper")
                    {
                        if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                            context_param_name = Some(&pat_ident.ident);
                            break;
                        }
                    }
                }
            }
        }
    }

    let context_param_name = match context_param_name {
        Some(name) => name,
        None => {
            eprintln!("Failed to find a parameter of type ContextWrapper<F>");
            return TokenStream::new(); // Return an empty TokenStream to avoid panic
        }
    };

    let fn_name = function.sig.ident.to_string();
    let original_body = &function.block;

    let wrapped_body = quote! {
        {
            #context_param_name.push_context(log::Level::Debug, #fn_name);
            let result = (|| #original_body)();
            #context_param_name.pop_context();
            result
        }
    };

    function.block = syn::parse2(wrapped_body).unwrap();
    TokenStream::from(quote!(#function))
}
