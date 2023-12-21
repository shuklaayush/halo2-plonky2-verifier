#[macro_export]
macro_rules! num_advice {
    ($ctx:expr, $label:expr, $exp:expr) => {{
        let before = $ctx.advice.len();
        let res = $exp;
        let after = $ctx.advice.len();
        println!("{}: {}", $label, after - before);
        res
    }};
}
