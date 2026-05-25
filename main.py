import click
import json
from utils.helpers import validate_url, check_security_headers

@click.command()
@click.option('--target', '-t', required=True, help='The target URL to perform security header auditing on.')
@click.option('--json-output', '-j', is_flag=True, help='Output the audit results in JSON format.')
def main(target: str, json_output: bool):
    """Security Audit CLI Tool - Validates HTTP response security configs."""
    click.echo(click.style(f"[*] Starting security audit for: {target}", fg='cyan'))
    
    if not validate_url(target):
        click.echo(click.style(f"[!] Error: The URL '{target}' is invalid. Please include scheme (e.g., https://)", fg='red'), err=True)
        return
    
    results = check_security_headers(target)
    
    if json_output:
        click.echo(json.dumps(results, indent=2))
        return
        
    click.echo("\n--- Audit Summary ---")
    if results["secure"]:
        click.echo(click.style("[+] Success: All key security headers are present!", fg='green'))
    else:
        click.echo(click.style("[-] Warnings: Missing recommended security configurations found.", fg='yellow'))
        
    click.echo("\n--- Detailed Findings ---")
    for finding in results["findings"]:
        if "error" in finding:
            click.echo(click.style(f"[Error] {finding['error']}", fg='red'))
        elif finding.get("status") == "Missing":
            click.echo(click.style(f"[MISSING] {finding['header']} -> {finding['risk_implication']}", fg='red'))
        else:
            click.echo(click.style(f"[PRESENT] {finding['header']}: {finding['value']}", fg='green'))

if __name__ == '__main__':
    main()