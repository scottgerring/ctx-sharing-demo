use opentelemetry::{global, trace::{Tracer, TracerProvider, TraceContextExt}, Context};

fn main() {
    let tracer_provider = datadog_opentelemetry::tracing()
        .with_config(
            dd_trace::Config::builder()
                .set_service("test".to_string())
                .build(),
        )
        .init();
    
    let tracer = tracer_provider.tracer("test");
    
    // Create parent span
    let parent_span = tracer.start("parent");
    println!("Parent span created with span_id: {:?}", parent_span.span_context().span_id());
    
    let parent_cx = Context::current_with_span(parent_span);
    println!("Parent context local_root_span_id: {:?}", parent_cx.local_root_span_id());
    
    let _guard = parent_cx.attach();
    println!("After attach, Context::current().local_root_span_id(): {:?}", Context::current().local_root_span_id());
    
    // Create child span
    let child_span = tracer.span_builder("child").start_with_context(&tracer, &Context::current());
    println!("Child span created with span_id: {:?}", child_span.span_context().span_id());
    println!("Child span local_root_span_id: {:?}", child_span.local_root_span_id());
}
