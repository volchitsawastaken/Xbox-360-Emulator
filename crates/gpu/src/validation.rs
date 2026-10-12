//! Headless wgpu validation: render offscreen and read back.
//!
//! Early M5 milestone only. Proves the host encoder path works; it is
//! not Xenos translation. Functions return `Ok(false)` when no adapter
//! exists so headless machines skip instead of failing.

use x360_common::{EmuError, Result};

const W: u32 = 64;
const H: u32 = 64;

const SHADER: &str = r#"
@vertex
fn vs(@builtin(vertex_index) i: u32) -> @builtin(position) vec4<f32> {
  var p = array<vec2<f32>, 3>(
    vec2<f32>(0.0, 0.5),
    vec2<f32>(-0.5, -0.5),
    vec2<f32>(0.5, -0.5));
  return vec4<f32>(p[i], 0.0, 1.0);
}

@fragment
fn fs() -> @location(0) vec4<f32> {
  return vec4<f32>(1.0, 0.0, 0.0, 1.0);
}
"#;

fn unorm(byte: u8) -> f64 {
    byte as f64 / 255.0
}

async fn headless_device() -> Result<Option<(wgpu::Device, wgpu::Queue)>> {
    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::default());
    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: true,
        })
        .await;
    let adapter = match adapter {
        Some(a) => a,
        None => {
            log::warn!("gpu validation: no adapter, skipping");
            return Ok(None);
        }
    };
    let (device, queue) = adapter
        .request_device(
            &wgpu::DeviceDescriptor {
                label: Some("x360-validate"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::default(),
                memory_hints: wgpu::MemoryHints::default(),
            },
            None,
        )
        .await
        .map_err(|e| EmuError::Other(format!("device request: {}", e)))?;
    Ok(Some((device, queue)))
}

fn make_target(device: &wgpu::Device) -> (wgpu::Texture, wgpu::TextureView, wgpu::Buffer) {
    let texture = device.create_texture(&wgpu::TextureDescriptor {
        label: Some("x360-rt"),
        size: wgpu::Extent3d {
            width: W,
            height: H,
            depth_or_array_layers: 1,
        },
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: wgpu::TextureFormat::Rgba8Unorm,
        usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
        view_formats: &[],
    });
    let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
    // 64px * 4B = 256, satisfies COPY_BYTES_PER_ROW_ALIGNMENT.
    let buf = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("x360-read"),
        size: (W * H * 4) as u64,
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });
    (texture, view, buf)
}

fn submit_copy(
    queue: &wgpu::Queue,
    encoder: wgpu::CommandEncoder,
    texture: &wgpu::Texture,
    buf: &wgpu::Buffer,
) {
    let mut encoder = encoder;
    encoder.copy_texture_to_buffer(
        wgpu::ImageCopyTexture {
            texture,
            mip_level: 0,
            origin: wgpu::Origin3d::ZERO,
            aspect: wgpu::TextureAspect::All,
        },
        wgpu::ImageCopyBuffer {
            buffer: buf,
            layout: wgpu::ImageDataLayout {
                offset: 0,
                bytes_per_row: Some(W * 4),
                rows_per_image: Some(H),
            },
        },
        wgpu::Extent3d {
            width: W,
            height: H,
            depth_or_array_layers: 1,
        },
    );
    queue.submit(Some(encoder.finish()));
}

fn read_pixels(device: &wgpu::Device, buf: &wgpu::Buffer) -> Result<Vec<u8>> {
    let slice = buf.slice(..);
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |r| {
        let _ = tx.send(r);
    });
    device.poll(wgpu::Maintain::Wait);
    rx.recv()
        .map_err(|e| EmuError::Other(format!("map recv: {}", e)))?
        .map_err(|e| EmuError::Other(format!("map: {:?}", e)))?;
    let out = slice.get_mapped_range().to_vec();
    buf.unmap();
    Ok(out)
}

/// Render and return true when the center pixel is red.
/// Returns `Ok(false)` when no adapter is available (skip).
pub fn validate_triangle() -> Result<bool> {
    pollster::block_on(async {
        let Some((device, queue)) = headless_device().await? else {
            return Ok(false);
        };

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("tri"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("tri-pipe"),
            layout: None,
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: "vs",
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                buffers: &[],
            },
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: "fs",
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format: wgpu::TextureFormat::Rgba8Unorm,
                    blend: None,
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            multiview: None,
            cache: None,
        });

        let (texture, view, buf) = make_target(&device);
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("tri-enc"),
        });
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("tri-pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });
            pass.set_pipeline(&pipeline);
            pass.draw(0..3, 0..1);
        }
        submit_copy(&queue, encoder, &texture, &buf);
        let data = read_pixels(&device, &buf)?;

        // Scan center rows for a red pixel (R high, G/B low).
        let mut found = false;
        for y in (H / 4)..(3 * H / 4) {
            for x in 0..W {
                let i = ((y * W + x) * 4) as usize;
                if data[i] > 128 && data[i + 1] < 128 && data[i + 2] < 128 {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        Ok(found)
    })
}

/// Clear to `color` (RGBA8) and check the center pixel matches exactly.
/// Used by the bridge to prove guest state reaches host pixels.
/// Returns `Ok(false)` when no adapter is available (skip).
pub fn render_clear(color: [u8; 4]) -> Result<bool> {
    pollster::block_on(async {
        let Some((device, queue)) = headless_device().await? else {
            return Ok(false);
        };
        let (texture, view, buf) = make_target(&device);
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("clear-enc"),
        });
        {
            let _pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("clear-pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color {
                            r: unorm(color[0]),
                            g: unorm(color[1]),
                            b: unorm(color[2]),
                            a: unorm(color[3]),
                        }),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });
        }
        submit_copy(&queue, encoder, &texture, &buf);
        let data = read_pixels(&device, &buf)?;
        let i = (((H / 2) * W + (W / 2)) * 4) as usize;
        Ok(data[i..i + 4] == color)
    })
}
