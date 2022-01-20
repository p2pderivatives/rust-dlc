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

/// Implements the [`lightning::util::ser::Writeable`] trait for an enum as a TLV.
#[macro_export]
macro_rules! impl_dlc_writeable_enum_as_tlv {
    ($st:ident, $(($variant_id: expr, $variant_name: ident)), *;) => {
        impl Writeable for $st {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
                match self {
                    $($st::$variant_name(ref field) => {
                        $crate::ser_impls::BigSize($variant_id as u64).write(w)?;
                        $crate::ser_impls::BigSize(field.serialized_length() as u64).write(w)?;
                        field.write(w)?;
                    }),*
                };
				Ok(())
            }
        }

        impl Readable for $st {
			fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
                let id: $crate::ser_impls::BigSize = Readable::read(r)?;
                match id.0 {
                    $($variant_id => {
                        let _ : $crate::ser_impls::BigSize = Readable::read(r)?;
						Ok($st::$variant_name(Readable::read(r)?))
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
