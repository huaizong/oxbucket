error[E0252]: the name `Path` is defined multiple times
  --> src\main.rs:27:15
   |
21 |     path::{Path, PathBuf},
   |            ---- previous import of the type `Path` here
--
error[E0107]: struct takes 0 generic arguments but 1 generic argument was supplied
    --> src\main.rs:122:19
     |
 122 |     Path(bucket): Path<String>,
     |                   ^^^^-------- help: remove the unnecessary generics
--
error[E0107]: struct takes 0 generic arguments but 1 generic argument was supplied
    --> src\main.rs:212:26
     |
 212 |     Path((bucket, key)): Path<(String, String)>,
     |                          ^^^^------------------ help: remove the unnecessary generics
--
error[E0277]: the size for values of type `[u8]` cannot be known at compilation time
    --> src\main.rs:122:19
     |
 122 |     Path(bucket): Path<String>,
     |                   ^^^^^^^^^^^^ doesn't have a size known at compile-time
--
error[E0277]: the size for values of type `[u8]` cannot be known at compilation time
    --> src\main.rs:122:5
     |
 122 |     Path(bucket): Path<String>,
     |     ^^^^^^^^^^^^ doesn't have a size known at compile-time
--
error[E0308]: mismatched types
    --> src\main.rs:122:5
     |
 122 |     Path(bucket): Path<String>,
     |     ^^^^^^^^^^^^ expected `Path`, found `Path<_>`
--
error[E0277]: the size for values of type `[u8]` cannot be known at compilation time
    --> src\main.rs:212:26
     |
 212 |     Path((bucket, key)): Path<(String, String)>,
     |                          ^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
--
error[E0277]: the size for values of type `[u8]` cannot be known at compilation time
    --> src\main.rs:212:5
     |
 212 |     Path((bucket, key)): Path<(String, String)>,
     |     ^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
--
error[E0308]: mismatched types
    --> src\main.rs:212:5
     |
 212 |     Path((bucket, key)): Path<(String, String)>,
     |     ^^^^^^^^^^^^^^^^^^^ expected `Path`, found `Path<_>`
--
error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\main.rs:214:30
    |
214 |     let resource = format!("/{bucket}/{key}");
    |                              ^^^^^^^^ doesn't have a size known at compile-time
--
