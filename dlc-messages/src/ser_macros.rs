//! Set of macro to help implementing the [`lightning::util::ser::Writeable`] trait.

/// Writes a field to a writer.
#[macro_export]
macro_rules! field_write {
    ($stream: expr, $field: expr, writeable) => {
        $field.write($stream)?;
    };
    ($stream: expr, $field: expr, {cb_writeable, $w_cb: expr, $r_cb: expr}) => {
        $w_cb(&$field, $stream)?;
    };
    ($stream: expr, $field: expr, string) => {
        $crate::ser_impls::write_string(&$field, $stream)?;
    };
    ($stream: expr, $field: expr, vec) => {
        $crate::ser_impls::write_vec(&$field, $stream)?;
    };
    ($stream: expr, $field: expr, {vec_cb, $w_cb: expr, $r_cb: expr}) => {
        $crate::ser_impls::write_vec_cb(&$field, $stream, &$w_cb)?;
    };
    ($stream: expr, $field: expr, {vec_u16_cb, $w_cb: expr, $r_cb: expr}) => {
        $crate::ser_impls::write_vec_u16_cb(&$field, $stream, &$w_cb)?;
    };
    ($stream: expr, $field: expr, float) => {
        $crate::ser_impls::write_f64($field, $stream)?;
    };
    ($stream: expr, $field: expr, usize) => {
        $crate::ser_impls::write_usize(&$field, $stream)?;
    };
    ($stream: expr, $field: expr, {option_cb, $w_cb: expr, $r_cb: expr}) => {
        $crate::ser_impls::write_option_cb(&$field, $stream, &$w_cb)?;
    };
    ($stream: expr, $field: expr, option) => {
        $crate::ser_impls::write_option(&$field, $stream)?;
    };
    ($stream: expr, $field: expr, {vec_tlv, $st:ident,$(($variant_id: expr, $variant_name: ident, {$(($field_in: ident, $field_ty_in:tt)),*})),*; $(($tuple_variant_id: expr, $tuple_variant_name: ident)),*}) => {
        write_vec_enum_tlv_stream!($stream, &$field, $st,$(($variant_id, $variant_name, {$(($field_in, $field_ty_in)),*})),*; $(($tuple_variant_id, $tuple_variant_name)),*);
    };
}

/// Reads a field from a reader.
#[macro_export]
macro_rules! field_read {
    ($stream: expr, writeable) => {
        Readable::read($stream)?
    };
    ($stream: expr, {cb_writeable, $w_cb: expr, $r_cb: expr}) => {
        $r_cb($stream)?
    };
    ($stream: expr, string) => {
        $crate::ser_impls::read_string($stream)?
    };
    ($stream: expr, vec) => {
        $crate::ser_impls::read_vec($stream)?
    };
    ($stream: expr, {vec_cb, $w_cb: expr, $r_cb: expr}) => {
        $crate::ser_impls::read_vec_cb($stream, &$r_cb)?
    };
    ($stream: expr, {vec_u16_cb, $w_cb: expr, $r_cb: expr}) => {
        $crate::ser_impls::read_vec_u16_cb($stream, &$r_cb)?
    };
    ($stream: expr, float) => {
        $crate::ser_impls::read_f64($stream)?
    };
    ($stream: expr, usize) => {
        $crate::ser_impls::read_usize($stream)?
    };
    ($stream: expr, {option_cb, $w_cb: expr, $r_cb: expr}) => {
        $crate::ser_impls::read_option_cb($stream, &$r_cb)?
    };
    ($stream: expr, option) => {
        $crate::ser_impls::read_option($stream)?
    };
    ($stream: expr, {vec_tlv, $st:ident,$(($variant_id: expr, $variant_name: ident, {$(($field: ident, $field_ty:tt)),*})),*; $(($tuple_variant_id: expr, $tuple_variant_name: ident)),*}) => {
        {
            let mut vec = Vec::new();
            read_vec_enum_tlv!($stream, vec, $st,$(($variant_id, $variant_name, {$(($field, $field_ty)),*})),*; $(($tuple_variant_id, $tuple_variant_name)),*);
            vec
        }
    };
}

/// Implements the [`lightning::util::ser::Writeable`] trait for a struct available
/// in this crate.
#[macro_export]
macro_rules! impl_dlc_writeable {
    ($st:ident, {$(($field: ident, $fieldty: tt)), *} ) => {
        impl Writeable for $st {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
				$(
                    field_write!(w, self.$field, $fieldty);
                )*
				Ok(())
            }
        }

        impl Readable for $st {
			fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
                Ok(Self {
                    $(
                        $field: field_read!(r, $fieldty),
                    )*
                })
            }
        }
    };
}

/// Implements the [`lightning::util::ser::Writeable`] trait for a struct external
/// to this crate.
#[macro_export]
macro_rules! impl_dlc_writeable_external {
    ($st: ident $(< $gen: ident $(< $gen2: ident >)?> )? , $name: ident, {$(($field: ident, $fieldty: tt)), *} ) => {
        /// Module containing write and read functions for $name
        pub mod $name {
            use super::*;
            use lightning::ln::msgs::DecodeError;
            use lightning::util::ser::Writer;
            /// Function to write $name
            pub fn write<W: Writer>($name: &$st<$($gen$(<$gen2>)?)?>, w: &mut W) -> Result<(), ::std::io::Error> {
                $(
                    field_write!(w, $name.$field, $fieldty);
                )*
                Ok(())
            }

            /// Function to read $name
            pub fn read<R: std::io::Read>(r: &mut R) -> Result<$st<$($gen$(<$gen2>)?)?>, DecodeError> {
                Ok($st {
                    $(
                        $field: field_read!(r, $fieldty),
                    )*
                })
            }
        }
    };
}

/// Writes a vec of enum as a TLV stream.
#[macro_export]
macro_rules! write_vec_enum_tlv_stream {
    ($stream:expr, $vec: expr, $st:ident,$(($variant_id: expr, $variant_name: ident, {$(($field: ident, $field_ty:tt)),*})),*; $(($tuple_variant_id: expr, $tuple_variant_name: ident)),*) => {
        $crate::ser_impls::BigSize($vec.len() as u64).write($stream)?;
        for el in $vec {
            match el {
                $($st::$tuple_variant_name(ref field) => {
                    $crate::ser_impls::BigSize($tuple_variant_id as u64).write($stream)?;
                    $crate::ser_impls::BigSize(field.serialized_length() as u64).write($stream)?;
                    field.write($stream)?;
                }),*
                $($st::$variant_name{ $(ref $field),* } => {
                    $crate::ser_impls::BigSize($variant_id as u64).write($stream)?;
                    let mut size : usize = 0;
                    $(
                        let mut length_calc = crate::ser_impls::LengthCalculatingWriter(0);
                        field_write!(&mut length_calc, $field, $field_ty);
                        size += length_calc.0;
                    )*
                    $crate::ser_impls::BigSize(size as u64).write($stream)?;
                    $(
                        field_write!($stream, $field, $field_ty);
                    )*
                }),*
            };
        }
    }
}

///
#[macro_export]
macro_rules! read_vec_enum_tlv {
    ($stream: expr, $vec:ident, $st:ident,$(($variant_id: expr, $variant_name: ident, {$(($field: ident, $field_ty:tt)),*})),*; $(($tuple_variant_id: expr, $tuple_variant_name: ident)),*) => {
            let size : $crate::ser_impls::BigSize = Readable::read($stream)?;
            let mut last_seen = None;
            for _ in 0..(size.0 as usize) {
                let id: $crate::ser_impls::BigSize = Readable::read($stream)?;
                let size : $crate::ser_impls::BigSize = Readable::read($stream)?;
                if let Some(last) = last_seen {
                    if last == id || last >= id {
                        return Err(DecodeError::InvalidValue);
                    }
                }
                last_seen = Some(id.clone());
                match id.0 {
                    $($tuple_variant_id => {
                        $vec.push($st::$tuple_variant_name(Readable::read($stream)));
                    }),*
                    $($variant_id => {
                        $vec.push($st::$variant_name {
                            $(
                                $field: field_read!($stream, $field_ty)
                            ),*
                        });
                    }),*
                    x if x % 2 == 0 => {
                        return Err(DecodeError::UnknownRequiredFeature)
                    },
                    _ => {
                        $stream.read_exact(&mut vec![0u8; size.0 as usize])?;
                    }
                }
        }
    }
}

/// Implements the [`lightning::util::ser::Writeable`] trait for an enum external
/// to this crate.
#[macro_export]
macro_rules! impl_dlc_writeable_external_enum {
    ($st:ident $(<$gen: ident>)?, $name: ident, $(($variant_id: expr, $variant_name: ident, $variant_mod: ident)), * ) => {
        mod $name {
            use super::*;

			pub fn write<W: Writer>($name: &$st$(<$gen>)?, w: &mut W) -> Result<(), ::std::io::Error> {
                match $name {
                    $($st::$variant_name(ref field) => {
                        let id : u8 = $variant_id;
                        id.write(w)?;
                        $variant_mod::write(field, w)?;
                    }),*
                };
				Ok(())
            }

			pub fn read<R: std::io::Read>(r: &mut R) -> Result<$st$(<$gen>)?, DecodeError> {
                let id: u8 = Readable::read(r)?;
                match id {
                    $($variant_id => {
						Ok($st::$variant_name($variant_mod::read(r)?))
					}),*
					_ => {
						Err(DecodeError::UnknownRequiredFeature)
					},
                }
            }
        }
    };
}

/// Implements the [`lightning::util::ser::Writeable`] trait for an enum.
#[macro_export]
macro_rules! impl_dlc_writeable_enum {
    ($st:ident, $(($tuple_variant_id: expr, $tuple_variant_name: ident)), *;
    $(($variant_id: expr, $variant_name: ident, {$(($field: ident, $fieldty: tt)),*})), *;
    $(($external_variant_id: expr, $external_variant_name: ident, $write_cb: expr, $read_cb: expr)), *;
    $(($simple_variant_id: expr, $simple_variant_name: ident)), *) => {
        impl Writeable for $st {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
                match self {
                    $($st::$tuple_variant_name(ref field) => {
                        let id : u8 = $tuple_variant_id;
                        id.write(w)?;
                        field.write(w)?;
                    }),*
                    $($st::$variant_name { $(ref $field),* } => {
                        let id : u8 = $variant_id;
                        id.write(w)?;
                        $(
                            field_write!(w, $field, $fieldty);
                        )*
                    }),*
                    $($st::$external_variant_name(ref field) => {
                        let id : u8 = $external_variant_id;
                        id.write(w)?;
                        $write_cb(field, w)?;
                    }),*
                    $($st::$simple_variant_name => {
                        let id : u8 = $simple_variant_id;
                        id.write(w)?;
                    }),*
                };
				Ok(())
            }
        }

        impl Readable for $st {
			fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
                let id: u8 = Readable::read(r)?;
                match id {
                    $($tuple_variant_id => {
						Ok($st::$tuple_variant_name(Readable::read(r)?))
					}),*
                    $($variant_id => {
                        Ok($st::$variant_name {
                            $(
                                $field: field_read!(r, $fieldty)
                            ),*
                        })
                    }),*
                    $($external_variant_id => {
						Ok($st::$external_variant_name($read_cb(r)?))
					}),*
                    $($simple_variant_id => {
						Ok($st::$simple_variant_name)
					}),*
					_ => {
						Err(DecodeError::UnknownRequiredFeature)
					},
                }
            }
        }
    };
}
