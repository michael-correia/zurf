use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

#[proc_macro_derive(TryFromU8)]
pub fn derive_try_from_u8(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let syn::Data::Enum(data_enum) = input.data else {
        return syn::Error::new_spanned(&name, "TryFromU8 only supports enums")
            .to_compile_error()
            .into();
    };

    for v in &data_enum.variants {
        let Some((_, _)) = &v.discriminant else {
            return syn::Error::new_spanned(&v.ident, "variant must have an explicit value")
                .to_compile_error()
                .into();
        };
    }

    let (variants, discriminants): (Vec<syn::Ident>, Vec<syn::Expr>) = data_enum
        .variants
        .iter()
        .map(|v| (v.ident.clone(), v.discriminant.as_ref().unwrap().1.clone()))
        .unzip();

    quote! {
        impl TryFrom<u8> for #name {
             type Error = u8;
             fn try_from (value: u8) -> std::result::Result<Self, Self::Error> {
                match value {
                    #( #discriminants => Ok(Self::#variants), )*
                    _ => Err(value),
                }
             }
        }

        impl From<#name> for u8 {
            fn from(value: #name) -> Self {
                value as u8
            }
        }
    }
    .into()
}
