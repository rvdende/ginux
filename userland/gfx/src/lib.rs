//! Software drawing shared by the Ginux compositor and its clients: a
//! clipped canvas over 32-bit XRGB/ARGB pixels and an 8x8 bitmap font.

use font8x8::{UnicodeFonts, BASIC_FONTS};

/// Width and height of one glyph in pixels at scale 1.
pub const GLYPH: i32 = 8;

/// An owned image in Wayland ARGB8888 layout (premultiplied alpha).
#[derive(Clone, Default)]
pub struct Image {
    pub width: i32,
    pub height: i32,
    pub pixels: Vec<u32>,
    /// False when the alpha channel must be honoured (ARGB8888).
    pub opaque: bool,
}

/// A clipped view of a pixel buffer that drawing operations write into.
pub struct Canvas<'a> {
    pub pixels: &'a mut [u32],
    pub width: i32,
    pub height: i32,
}

impl<'a> Canvas<'a> {
    pub fn new(pixels: &'a mut [u32], width: i32, height: i32) -> Self {
        assert!(pixels.len() >= (width.max(0) * height.max(0)) as usize);
        Self {
            pixels,
            width,
            height,
        }
    }

    /// Clips a rectangle to the canvas, returning (x0, y0, x1, y1).
    fn clip(&self, x: i32, y: i32, width: i32, height: i32) -> Option<(i32, i32, i32, i32)> {
        let x0 = x.max(0);
        let y0 = y.max(0);
        let x1 = x.saturating_add(width).min(self.width);
        let y1 = y.saturating_add(height).min(self.height);
        (x0 < x1 && y0 < y1).then_some((x0, y0, x1, y1))
    }

    pub fn fill(&mut self, x: i32, y: i32, width: i32, height: i32, color: u32) {
        let Some((x0, y0, x1, y1)) = self.clip(x, y, width, height) else {
            return;
        };
        for row in y0..y1 {
            let start = (row * self.width + x0) as usize;
            self.pixels[start..start + (x1 - x0) as usize].fill(color);
        }
    }

    /// Draws a one-pixel rectangle outline.
    pub fn outline(&mut self, x: i32, y: i32, width: i32, height: i32, color: u32) {
        self.fill(x, y, width, 1, color);
        self.fill(x, y + height - 1, width, 1, color);
        self.fill(x, y, 1, height, color);
        self.fill(x + width - 1, y, 1, height, color);
    }

    /// Darkens a rectangle by blending black at `alpha` (0-255) over it.
    pub fn shade(&mut self, x: i32, y: i32, width: i32, height: i32, alpha: u32) {
        let Some((x0, y0, x1, y1)) = self.clip(x, y, width, height) else {
            return;
        };
        let keep = 255 - alpha.min(255);
        for row in y0..y1 {
            let start = (row * self.width + x0) as usize;
            for pixel in &mut self.pixels[start..start + (x1 - x0) as usize] {
                *pixel = scale(*pixel, keep) | 0xff00_0000;
            }
        }
    }

    /// Copies `image` with its top-left corner at (x, y), blending
    /// premultiplied alpha unless the image is opaque.
    pub fn blit(&mut self, x: i32, y: i32, image: &Image) {
        let Some((x0, y0, x1, y1)) = self.clip(x, y, image.width, image.height) else {
            return;
        };
        let span = (x1 - x0) as usize;
        for row in y0..y1 {
            let source_start = ((row - y) * image.width + (x0 - x)) as usize;
            let source = &image.pixels[source_start..source_start + span];
            let start = (row * self.width + x0) as usize;
            let target = &mut self.pixels[start..start + span];
            if image.opaque {
                for (target, source) in target.iter_mut().zip(source) {
                    *target = *source | 0xff00_0000;
                }
            } else {
                for (target, source) in target.iter_mut().zip(source) {
                    *target = over(*source, *target);
                }
            }
        }
    }

    /// Draws one character with the 8x8 font scaled by `scale`; returns the
    /// advance in pixels.
    pub fn glyph(&mut self, x: i32, y: i32, character: char, color: u32, scale: i32) -> i32 {
        let glyph = BASIC_FONTS
            .get(character)
            .or_else(|| BASIC_FONTS.get('?'))
            .unwrap_or([0; 8]);
        for (row, bits) in glyph.iter().enumerate() {
            for column in 0..8 {
                if bits & (1 << column) != 0 {
                    self.fill(
                        x + column * scale,
                        y + row as i32 * scale,
                        scale,
                        scale,
                        color,
                    );
                }
            }
        }
        GLYPH * scale
    }

    /// Draws a single line of text, stopping before `max_width` pixels.
    pub fn text(&mut self, x: i32, y: i32, text: &str, color: u32, scale: i32, max_width: i32) {
        let mut cursor = x;
        for character in text.chars() {
            if cursor + GLYPH * scale > x + max_width {
                break;
            }
            cursor += self.glyph(cursor, y, character, color, scale);
        }
    }
}

/// Scales the colour channels of an XRGB pixel by `factor`/255.
fn scale(pixel: u32, factor: u32) -> u32 {
    let red = ((pixel >> 16) & 0xff) * factor / 255;
    let green = ((pixel >> 8) & 0xff) * factor / 255;
    let blue = (pixel & 0xff) * factor / 255;
    (red << 16) | (green << 8) | blue
}

/// Porter-Duff "over" for a premultiplied source on an opaque target.
fn over(source: u32, target: u32) -> u32 {
    match source >> 24 {
        255 => source,
        0 => target,
        alpha => {
            let keep = 255 - alpha;
            let red = (((source >> 16) & 0xff) + ((target >> 16) & 0xff) * keep / 255).min(255);
            let green = (((source >> 8) & 0xff) + ((target >> 8) & 0xff) * keep / 255).min(255);
            let blue = ((source & 0xff) + (target & 0xff) * keep / 255).min(255);
            0xff00_0000 | (red << 16) | (green << 8) | blue
        }
    }
}

/// An arrow pointer drawn by the compositor: '#' is the outline, '.' fill.
pub const CURSOR: [&str; 19] = [
    "#",
    "##",
    "#.#",
    "#..#",
    "#...#",
    "#....#",
    "#.....#",
    "#......#",
    "#.......#",
    "#........#",
    "#.........#",
    "#..........#",
    "#......#####",
    "#...#..#",
    "#..##..#",
    "#.#  #..#",
    "##   #..#",
    "      #..#",
    "      ###",
];

impl Canvas<'_> {
    pub fn cursor(&mut self, x: i32, y: i32) {
        for (row, line) in CURSOR.iter().enumerate() {
            for (column, cell) in line.bytes().enumerate() {
                let color = match cell {
                    b'#' => 0xff00_0000,
                    b'.' => 0xffff_ffff,
                    _ => continue,
                };
                self.fill(x + column as i32, y + row as i32, 1, 1, color);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_is_clipped() {
        let mut pixels = vec![0; 16];
        let mut canvas = Canvas::new(&mut pixels, 4, 4);
        canvas.fill(-2, -2, 4, 4, 1);
        canvas.fill(3, 3, 10, 10, 2);
        assert_eq!(pixels, [1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    }

    #[test]
    fn blit_blends_premultiplied_alpha() {
        let mut pixels = vec![0xff00_00ff; 1];
        let image = Image {
            width: 1,
            height: 1,
            pixels: vec![0x8080_0000],
            opaque: false,
        };
        Canvas::new(&mut pixels, 1, 1).blit(0, 0, &image);
        assert_eq!(pixels[0], 0xff80_007f);
    }

    #[test]
    fn text_stops_at_width() {
        let mut pixels = vec![0; 64 * 8];
        let mut canvas = Canvas::new(&mut pixels, 64, 8);
        canvas.text(0, 0, "WWWWWWWWWW", 1, 1, 20);
        assert!((0..8).all(|row| pixels[row * 64 + 20..row * 64 + 64].iter().all(|p| *p == 0)));
        assert!(pixels.contains(&1));
    }
}
