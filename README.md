<a name="top"></a>

![Operating System](https://img.shields.io/badge/platform-windows-blue)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/aplace-lab/amber-kawpow-miner/main.yml)
[![GitHub release](https://img.shields.io/github/v/release/aplace-lab/amber-kawpow-miner)](#)
[![GitHub release date](https://img.shields.io/github/release-date/aplace-lab/amber-kawpow-miner)](#)
[![GitHub last commit](https://img.shields.io/github/last-commit/aplace-lab/amber-kawpow-miner)](#)

## Table of Contents
- [About](#-about)
- [Documentation](#-documentation)
- [Development](#-development)
- [Feedback and Contributions](#-feedback-and-contributions)

## 🚀 About

**Amber Kawpow Miner** is a dual CPU/GPU miner utilising XMRig/TeamBlackMiner to automate processes based on the cost of electricity, designed for RavenCoin and Monero mining.

This application depends on the Amber Electric API to determine the current localised pricing, using individual/customisable thresholds.

## 📚 Documentation 

### Getting Started

After downloading and running the application, on first launch you'll be prompted to input values for authentication with the [Amber Electric API](https://app.amber.com.au/developers/), as well as mining details for your pools, wallets, etc.

#### <img src="https://app.amber.com.au/favicon.ico" width="16"> Amber Electric API

- Follow the prompts to [Generate a new Token](https://app.amber.com.au/developers/). This token is secret and will not be shown again, make sure you record this.
- Use the `GET /sites` endpoint to determine the Site ID for your account. This is unique to the location of your property.

#### 💰 Electricity Cost Threshold

There is a monetary value threshold for both CPU/GPU mining, formatted in $/kWh, which will automatically start/stop individual mining processes based on the current general use price of electricity (updated every 5 mins).

By default, CPU mining has a threshold of `$0.40/kWh`. This means that once the current price reaches `$0.40/kWh`, CPU mining will be stopped.

#### ⌛ Idle Time Threshold

Additionally, there is an option to track the device's idle time and only begin mining when both idle for the configured duration, and within the electricity cost parameters.

### Starting the miner

Once your configuration is complete, the miner can either be started manually, or automatically manage mining.

#### Automatic

- Check the `Auto Control Mining` box.
- The `Mining Control` section should now display the current status of the miner (either waiting for conditions to be met, or mining has started)

#### Manual

- Press the `Start Mining` button

## 📝 Development

To build the executable, follow these steps:

```shell
# Open a terminal (Command Prompt or PowerShell)

# Ensure Git is installed
# Visit https://git-scm.com to download and install console Git if not already installed

# Clone the repository
git clone https://github.com/aplace-lab/amber-kawpow-miner.git

# Navigate to the project directory
cd amber-kawpow-miner

# Install dependencies
pip install -r requirements.txt

# Test changes
python main.py

# Create the executable
pyinstaller main.py --noconsole --onefile
```

## 🤝 Feedback and Contributions

> [!IMPORTANT]
> Whether you have feedback on features, have encountered any bugs, or have suggestions for enhancements, please get in touch, or feel free to contribute by [submitting an issue](https://github.com/aplace-lab/amber-kawpow-miner/issues).

[Back to top](#top)