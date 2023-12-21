extern crate proc_macro;
extern crate quote;
extern crate syn;

use self::proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn count(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut function = parse_macro_input!(input as ItemFn);
    let fn_name = function.sig.ident.to_string();

    // Extract original function body
    let original_body = &function.block;

    // Create a new block that wraps the original function body
    let wrapped_body = quote! {
        {
            ctx.push_context(log::Level::Debug, #fn_name);
            let result = (|| #original_body)();
            ctx.pop_context();
            result
        }
    };

    // Replace the function body with the new wrapped body
    function.block = syn::parse2(wrapped_body).unwrap();

    // Convert the function back to tokens
    TokenStream::from(quote!(#function))
}
