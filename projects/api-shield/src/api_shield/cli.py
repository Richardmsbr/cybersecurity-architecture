"""CLI for API Shield."""

import asyncio
import json
import sys
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .core import APIEvent
from .engine import AnalysisEngine, EngineConfig, create_engine

app = typer.Typer(
    name="api-shield",
    help="Real-time API Security Analysis Platform",
    add_completion=False,
)
console = Console()


@app.command()
def analyze(
    method: str = typer.Argument(..., help="HTTP method (GET, POST, etc.)"),
    path: str = typer.Argument(..., help="Request path (e.g., /api/users/123)"),
    ip: str = typer.Option("127.0.0.1", "--ip", "-i", help="Client IP address"),
    user_id: Optional[str] = typer.Option(None, "--user", "-u", help="User ID"),
    headers: Optional[str] = typer.Option(None, "--headers", "-H", help="Headers as JSON"),
    response_code: Optional[int] = typer.Option(None, "--code", "-c", help="Response code"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Analyze a single API request for security threats."""

    async def run():
        engine = await create_engine()

        # Parse headers
        parsed_headers = {}
        if headers:
            try:
                parsed_headers = json.loads(headers)
            except json.JSONDecodeError:
                console.print("[red]Invalid JSON for headers[/red]")
                raise typer.Exit(1)

        # Create event
        event = APIEvent(
            request_id="cli-test",
            timestamp=datetime.utcnow(),
            method=method.upper(),
            path=path,
            client_ip=ip,
            user_id=user_id,
            headers=parsed_headers,
            response_code=response_code,
        )

        # Analyze
        result = await engine.analyze(event)
        await engine.shutdown()

        # Display results
        display_analysis_result(result, verbose)

        # Exit with non-zero if blocked
        if result.action.blocking:
            raise typer.Exit(1)

    asyncio.run(run())


@app.command()
def simulate(
    requests: int = typer.Option(100, "--requests", "-n", help="Number of requests to simulate"),
    attack_type: str = typer.Option(
        "mixed",
        "--attack",
        "-a",
        help="Attack type: normal, bola, brute_force, rate_limit, mixed"
    ),
    user_id: str = typer.Option("test_user", "--user", "-u", help="User ID for simulation"),
):
    """Simulate API traffic for testing detection capabilities."""

    async def run():
        engine = await create_engine()

        console.print(Panel(
            f"[bold]Simulating {requests} requests[/bold]\n"
            f"Attack type: [yellow]{attack_type}[/yellow]\n"
            f"User: [cyan]{user_id}[/cyan]",
            title="API Shield Simulation",
        ))

        # Generate events based on attack type
        events = generate_simulation_events(requests, attack_type, user_id)

        blocked = 0
        rate_limited = 0
        challenged = 0
        allowed = 0

        with console.status("[bold green]Analyzing requests...") as status:
            for i, event in enumerate(events):
                result = await engine.analyze(event)

                if result.action.blocking:
                    blocked += 1
                elif result.action.type.value == "rate_limit":
                    rate_limited += 1
                elif result.action.type.value == "challenge":
                    challenged += 1
                else:
                    allowed += 1

                if (i + 1) % 10 == 0:
                    status.update(f"[bold green]Processed {i + 1}/{requests} requests...")

        await engine.shutdown()

        # Display results
        table = Table(title="Simulation Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Percentage", style="green")

        total = blocked + rate_limited + challenged + allowed
        table.add_row("Blocked", str(blocked), f"{blocked/total*100:.1f}%")
        table.add_row("Rate Limited", str(rate_limited), f"{rate_limited/total*100:.1f}%")
        table.add_row("Challenged", str(challenged), f"{challenged/total*100:.1f}%")
        table.add_row("Allowed", str(allowed), f"{allowed/total*100:.1f}%")
        table.add_row("Total", str(total), "100%")

        console.print(table)

        # Show engine metrics
        metrics = engine.get_metrics()
        console.print(f"\n[bold]Processing Time:[/bold] avg={metrics['avg_processing_time_ms']:.2f}ms, max={metrics['max_processing_time_ms']:.2f}ms")

    asyncio.run(run())


@app.command()
def server(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to"),
    workers: int = typer.Option(4, "--workers", "-w", help="Number of workers"),
):
    """Start the API Shield server for real-time analysis."""
    console.print(Panel(
        f"[bold green]Starting API Shield Server[/bold green]\n\n"
        f"Host: [cyan]{host}[/cyan]\n"
        f"Port: [cyan]{port}[/cyan]\n"
        f"Workers: [cyan]{workers}[/cyan]\n\n"
        f"API Endpoints:\n"
        f"  POST /analyze - Analyze a request\n"
        f"  GET /metrics - Get engine metrics\n"
        f"  GET /health - Health check",
        title="API Shield",
    ))

    try:
        import uvicorn
        from .server import create_app

        api = create_app()
        uvicorn.run(api, host=host, port=port, workers=workers)
    except ImportError:
        console.print("[red]uvicorn not installed. Run: pip install uvicorn[/red]")
        raise typer.Exit(1)


@app.command()
def config(
    show: bool = typer.Option(False, "--show", "-s", help="Show current configuration"),
    generate: bool = typer.Option(False, "--generate", "-g", help="Generate sample config"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
):
    """Manage API Shield configuration."""
    if generate:
        sample_config = {
            "engine": {
                "block_threshold": 0.8,
                "rate_limit_threshold": 0.5,
                "challenge_threshold": 0.3,
                "monitor_threshold": 0.1,
                "parallel_detection": True,
                "timeout_seconds": 1.0,
            },
            "detectors": {
                "bola": {
                    "enabled": True,
                    "weight": 0.30,
                    "unique_threshold": 100,
                },
                "auth": {
                    "enabled": True,
                    "weight": 0.25,
                    "failed_threshold": 5,
                    "lockout_window_minutes": 15,
                },
                "rate": {
                    "enabled": True,
                    "weight": 0.20,
                    "global_limit": 1000,
                    "endpoint_limit": 100,
                },
                "behavioral": {
                    "enabled": True,
                    "weight": 0.25,
                    "min_requests_for_profile": 50,
                },
            },
            "integrations": {
                "prometheus": {
                    "enabled": False,
                    "port": 9090,
                },
                "redis": {
                    "enabled": False,
                    "url": "redis://localhost:6379",
                },
            },
        }

        config_json = json.dumps(sample_config, indent=2)

        if output:
            with open(output, "w") as f:
                f.write(config_json)
            console.print(f"[green]Configuration written to {output}[/green]")
        else:
            console.print_json(config_json)

    elif show:
        # Show default configuration
        default = EngineConfig()
        console.print(Panel(
            f"[bold]Engine Configuration[/bold]\n\n"
            f"Block Threshold: [red]{default.block_threshold}[/red]\n"
            f"Rate Limit Threshold: [yellow]{default.rate_limit_threshold}[/yellow]\n"
            f"Challenge Threshold: [blue]{default.challenge_threshold}[/blue]\n"
            f"Monitor Threshold: [green]{default.monitor_threshold}[/green]\n"
            f"Parallel Detection: {default.parallel_detection}\n"
            f"Timeout: {default.timeout_seconds}s",
            title="Current Configuration",
        ))
    else:
        console.print("[yellow]Use --show to display config or --generate to create sample[/yellow]")


@app.command()
def version():
    """Show API Shield version."""
    console.print("[bold]API Shield[/bold] v0.1.0")
    console.print("Real-time API Security Analysis Platform")


def display_analysis_result(result, verbose: bool = False):
    """Display analysis result in a formatted way."""
    # Risk score color
    if result.risk_score >= 0.8:
        score_color = "red"
        score_label = "CRITICAL"
    elif result.risk_score >= 0.5:
        score_color = "yellow"
        score_label = "HIGH"
    elif result.risk_score >= 0.3:
        score_color = "blue"
        score_label = "MEDIUM"
    else:
        score_color = "green"
        score_label = "LOW"

    # Main panel
    action_emoji = {
        "block": "🛑",
        "rate_limit": "⏳",
        "challenge": "🔐",
        "monitor": "👁️",
        "allow": "✅",
    }

    console.print(Panel(
        f"[bold {score_color}]Risk Score: {result.risk_score:.2f} ({score_label})[/bold {score_color}]\n\n"
        f"Action: {action_emoji.get(result.action.type.value, '❓')} [bold]{result.action.type.value.upper()}[/bold]\n"
        f"Reason: {result.action.reason or 'N/A'}\n"
        f"Processing Time: {result.processing_time_ms:.2f}ms\n"
        f"Detectors Triggered: {', '.join(result.detectors_triggered) or 'None'}",
        title="Analysis Result",
        border_style=score_color,
    ))

    if verbose and result.signals:
        # Signals table
        table = Table(title="Detection Signals")
        table.add_column("Signal", style="cyan")
        table.add_column("Score", style="magenta")

        for signal, score in sorted(result.signals.items(), key=lambda x: -x[1]):
            table.add_row(signal, f"{score:.3f}")

        console.print(table)


def generate_simulation_events(count: int, attack_type: str, user_id: str):
    """Generate simulation events based on attack type."""
    import random
    import uuid

    events = []

    for i in range(count):
        # Base event
        event_kwargs = {
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow(),
            "method": "GET",
            "path": "/api/users/123",
            "client_ip": "192.168.1.1",
            "user_id": user_id,
            "headers": {"user-agent": "Mozilla/5.0"},
        }

        if attack_type == "normal":
            # Normal traffic patterns
            event_kwargs["path"] = random.choice([
                "/api/users/profile",
                "/api/orders",
                "/api/products",
            ])

        elif attack_type == "bola":
            # BOLA attack - sequential ID enumeration
            event_kwargs["path"] = f"/api/users/{1000 + i}"

        elif attack_type == "brute_force":
            # Brute force - multiple auth failures
            event_kwargs["path"] = "/api/auth/login"
            event_kwargs["method"] = "POST"
            event_kwargs["response_code"] = 401 if i % 3 != 0 else 200

        elif attack_type == "rate_limit":
            # Rate limit - many requests quickly
            event_kwargs["path"] = "/api/data"

        elif attack_type == "mixed":
            # Mix of attack types
            r = random.random()
            if r < 0.3:
                # Normal
                event_kwargs["path"] = random.choice(["/api/users/profile", "/api/orders"])
            elif r < 0.5:
                # BOLA
                event_kwargs["path"] = f"/api/users/{1000 + i}"
            elif r < 0.7:
                # Brute force
                event_kwargs["path"] = "/api/auth/login"
                event_kwargs["response_code"] = 401
            else:
                # Rate limit
                event_kwargs["path"] = "/api/data"

        events.append(APIEvent(**event_kwargs))

    return events


def main():
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
