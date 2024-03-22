// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck
/**
 * Ampli - A strong typed wrapper for your Analytics
 *
 * This file is generated by Amplitude.
 * To update run 'ampli pull web'
 *
 * Required dependencies: @amplitude/analytics-browser@^1.3.0
 * Tracking Plan Version: 1
 * Build: 1.0.0
 * Runtime: browser:typescript-ampli-v2
 *
 * [View Tracking Plan](https://data.amplitude.com/mystenlabs/Sui%20Explorer/events/main/latest)
 *
 * [Full Setup Instructions](https://data.amplitude.com/mystenlabs/Sui%20Explorer/implementation/web)
 */

import * as amplitude from '@amplitude/analytics-browser';

export type Environment = 'production' | 'development';

export const ApiKey: Record<Environment, string> = {
	production: '1c341785c734c98d9f2dca06128b914a',
	development: '94db6502f3853b6f35ccd070f6d37082',
};

/**
 * Default Amplitude configuration options. Contains tracking plan information.
 */
export const DefaultConfiguration: BrowserOptions = {
	plan: {
		version: '1',
		branch: 'main',
		source: 'web',
		versionId: 'e04b8300-7375-4e37-a47e-7eb097e55c65',
	},
	...{
		ingestionMetadata: {
			sourceName: 'browser-typescript-ampli',
			sourceVersion: '2.0.0',
		},
	},
};

export interface LoadOptionsBase {
	disabled?: boolean;
}

export type LoadOptionsWithEnvironment = LoadOptionsBase & {
	environment: Environment;
	client?: { configuration?: BrowserOptions };
};
export type LoadOptionsWithApiKey = LoadOptionsBase & {
	client: { apiKey: string; configuration?: BrowserOptions };
};
export type LoadOptionsWithClientInstance = LoadOptionsBase & {
	client: { instance: BrowserClient };
};

export type LoadOptions =
	| LoadOptionsWithEnvironment
	| LoadOptionsWithApiKey
	| LoadOptionsWithClientInstance;

export interface IdentifyProperties {
	/**
	 * The Sui network that the user is currently interacting with.
	 */
	activeNetwork: string;
	/**
	 * The domain (e.g., suiexplorer.com) of a given page.
	 */
	pageDomain: string;
	/**
	 * The path (e.g., /validators) of a given page.
	 */
	pagePath: string;
	/**
	 * The full URL (e.g., suiexplorer.com/validators) of a given page.
	 */
	pageUrl: string;
}

export interface ActivatedTooltipProperties {
	tooltipLabel: string;
}

export interface ClickedCurrentEpochCardProperties {
	/**
	 * An epoch or period of time.
	 *
	 * | Rule | Value |
	 * |---|---|
	 * | Type | integer |
	 */
	epoch: number;
}

export interface ClickedSearchResultProperties {
	searchCategory: string;
	searchQuery: string;
}

export interface ClickedValidatorRowProperties {
	/**
	 * The source flow where the user came from.
	 */
	sourceFlow: string;
	/**
	 * The address of a validator.
	 */
	validatorAddress: string;
	/**
	 * The name of a validator.
	 */
	validatorName: string;
}

export interface CompletedSearchProperties {
	searchQuery: string;
}

export interface RedirectToExternalExplorerProperties {
	name: string;
	url: string;
}

export interface SwitchedNetworkProperties {
	toNetwork: string;
}

export class Identify implements BaseEvent {
	event_type = amplitude.Types.SpecialEventType.IDENTIFY;

	constructor(public event_properties: IdentifyProperties) {
		this.event_properties = event_properties;
	}
}

export class ActivatedTooltip implements BaseEvent {
	event_type = 'activated tooltip';

	constructor(public event_properties: ActivatedTooltipProperties) {
		this.event_properties = event_properties;
	}
}

export class ClickedCurrentEpochCard implements BaseEvent {
	event_type = 'clicked current epoch card';

	constructor(public event_properties: ClickedCurrentEpochCardProperties) {
		this.event_properties = event_properties;
	}
}

export class ClickedSearchResult implements BaseEvent {
	event_type = 'clicked search result';

	constructor(public event_properties: ClickedSearchResultProperties) {
		this.event_properties = event_properties;
	}
}

export class ClickedValidatorRow implements BaseEvent {
	event_type = 'clicked validator row';

	constructor(public event_properties: ClickedValidatorRowProperties) {
		this.event_properties = event_properties;
	}
}

export class CompletedSearch implements BaseEvent {
	event_type = 'completed search';

	constructor(public event_properties: CompletedSearchProperties) {
		this.event_properties = event_properties;
	}
}

export class OpenedSuiExplorer implements BaseEvent {
	event_type = 'opened sui explorer';
}

export class RedirectToExternalExplorer implements BaseEvent {
	event_type = 'redirect to external explorer';

	constructor(public event_properties: RedirectToExternalExplorerProperties) {
		this.event_properties = event_properties;
	}
}

export class SwitchedNetwork implements BaseEvent {
	event_type = 'switched network';

	constructor(public event_properties: SwitchedNetworkProperties) {
		this.event_properties = event_properties;
	}
}

export type PromiseResult<T> = { promise: Promise<T | void> };

const getVoidPromiseResult = () => ({ promise: Promise.resolve() });

// prettier-ignore
export class Ampli {
  private disabled: boolean = false;
  private amplitude?: BrowserClient;

  get client(): BrowserClient {
    this.isInitializedAndEnabled();
    return this.amplitude!;
  }

  get isLoaded(): boolean {
    return this.amplitude != null;
  }

  private isInitializedAndEnabled(): boolean {
    if (!this.amplitude) {
      console.error('ERROR: Ampli is not yet initialized. Have you called ampli.load() on app start?');
      return false;
    }
    return !this.disabled;
  }

  /**
   * Initialize the Ampli SDK. Call once when your application starts.
   *
   * @param options Configuration options to initialize the Ampli SDK with.
   */
  load(options: LoadOptions): PromiseResult<void> {
    this.disabled = options.disabled ?? false;

    if (this.amplitude) {
      console.warn('WARNING: Ampli is already intialized. Ampli.load() should be called once at application startup.');
      return getVoidPromiseResult();
    }

    let apiKey: string | null = null;
    if (options.client && 'apiKey' in options.client) {
      apiKey = options.client.apiKey;
    } else if ('environment' in options) {
      apiKey = ApiKey[options.environment];
    }

    if (options.client && 'instance' in options.client) {
      this.amplitude = options.client.instance;
    } else if (apiKey) {
      this.amplitude = amplitude.createInstance();
      const configuration = (options.client && 'configuration' in options.client) ? options.client.configuration : {};
      return this.amplitude.init(apiKey, undefined, { ...DefaultConfiguration, ...configuration });
    } else {
      console.error("ERROR: ampli.load() requires 'environment', 'client.apiKey', or 'client.instance'");
    }

    return getVoidPromiseResult();
  }

  /**
   * Identify a user and set user properties.
   *
   * @param userId The user's id.
   * @param properties The user properties.
   * @param options Optional event options.
   */
  identify(
    userId: string | undefined,
    properties: IdentifyProperties,
    options?: EventOptions,
  ): PromiseResult<Result> {
    if (!this.isInitializedAndEnabled()) {
      return getVoidPromiseResult();
    }

    if (userId) {
      options = {...options,  user_id: userId};
    }

    const amplitudeIdentify = new amplitude.Identify();
    const eventProperties = properties;
    if (eventProperties != null) {
      for (const [key, value] of Object.entries(eventProperties)) {
        amplitudeIdentify.set(key, value);
      }
    }
    return this.amplitude!.identify(
      amplitudeIdentify,
      options,
    );
  }

 /**
  * Flush the event.
  */
  flush() : PromiseResult<Result> {
    if (!this.isInitializedAndEnabled()) {
      return getVoidPromiseResult();
    }

    return this.amplitude!.flush();
  }

  /**
   * Track event
   *
   * @param event The event to track.
   * @param options Optional event options.
   */
  track(event: Event, options?: EventOptions): PromiseResult<Result> {
    if (!this.isInitializedAndEnabled()) {
      return getVoidPromiseResult();
    }

    return this.amplitude!.track(event, undefined, options);
  }

  /**
   * activated tooltip
   *
   * [View in Tracking Plan](https://data.amplitude.com/mystenlabs/Sui%20Explorer/events/main/latest/activated%20tooltip)
   *
   * When users activate or open a tooltip in the application.
   *
   * Owner: William Robertson
   *
   * @param properties The event's properties (e.g. tooltipLabel)
   * @param options Amplitude event options.
   */
  activatedTooltip(
    properties: ActivatedTooltipProperties,
    options?: EventOptions,
  ) {
    return this.track(new ActivatedTooltip(properties), options);
  }

  /**
   * clicked current epoch card
   *
   * [View in Tracking Plan](https://data.amplitude.com/mystenlabs/Sui%20Explorer/events/main/latest/clicked%20current%20epoch%20card)
   *
   * When users click the current epoch card on the home page.
   *
   * Owner: William Robertson
   *
   * @param properties The event's properties (e.g. epoch)
   * @param options Amplitude event options.
   */
  clickedCurrentEpochCard(
    properties: ClickedCurrentEpochCardProperties,
    options?: EventOptions,
  ) {
    return this.track(new ClickedCurrentEpochCard(properties), options);
  }

  /**
   * clicked search result
   *
   * [View in Tracking Plan](https://data.amplitude.com/mystenlabs/Sui%20Explorer/events/main/latest/clicked%20search%20result)
   *
   * When users click a search result within the search bar.
   *
   * Owner: William Robertson
   *
   * @param properties The event's properties (e.g. searchCategory)
   * @param options Amplitude event options.
   */
  clickedSearchResult(
    properties: ClickedSearchResultProperties,
    options?: EventOptions,
  ) {
    return this.track(new ClickedSearchResult(properties), options);
  }

  /**
   * clicked validator row
   *
   * [View in Tracking Plan](https://data.amplitude.com/mystenlabs/Sui%20Explorer/events/main/latest/clicked%20validator%20row)
   *
   * When users click a validator list item in a table.
   *
   * Owner: William Robertson
   *
   * @param properties The event's properties (e.g. sourceFlow)
   * @param options Amplitude event options.
   */
  clickedValidatorRow(
    properties: ClickedValidatorRowProperties,
    options?: EventOptions,
  ) {
    return this.track(new ClickedValidatorRow(properties), options);
  }

  /**
   * completed search
   *
   * [View in Tracking Plan](https://data.amplitude.com/mystenlabs/Sui%20Explorer/events/main/latest/completed%20search)
   *
   * When users successfully search for something.
   *
   * Owner: William Robertson
   *
   * @param properties The event's properties (e.g. searchQuery)
   * @param options Amplitude event options.
   */
  completedSearch(
    properties: CompletedSearchProperties,
    options?: EventOptions,
  ) {
    return this.track(new CompletedSearch(properties), options);
  }

  /**
   * opened sui explorer
   *
   * [View in Tracking Plan](https://data.amplitude.com/mystenlabs/Sui%20Explorer/events/main/latest/opened%20sui%20explorer)
   *
   * When users first open Sui Explorer.
   *
   * Owner: William Robertson
   *
   * @param options Amplitude event options.
   */
  openedSuiExplorer(
    options?: EventOptions,
  ) {
    return this.track(new OpenedSuiExplorer(), options);
  }

  /**
   * redirect to external explorer
   *
   * [View in Tracking Plan](https://data.amplitude.com/mystenlabs/Sui%20Explorer/events/main/latest/redirect%20to%20external%20explorer)
   *
   * Metric to track which external explorers are being used, currently have suiscan and suivision
   *
   * @param properties The event's properties (e.g. name)
   * @param options Amplitude event options.
   */
  redirectToExternalExplorer(
    properties: RedirectToExternalExplorerProperties,
    options?: EventOptions,
  ) {
    return this.track(new RedirectToExternalExplorer(properties), options);
  }

  /**
   * switched network
   *
   * [View in Tracking Plan](https://data.amplitude.com/mystenlabs/Sui%20Explorer/events/main/latest/switched%20network)
   *
   * When users switch from one network to another.
   *
   * Owner: William Robertson
   *
   * @param properties The event's properties (e.g. toNetwork)
   * @param options Amplitude event options.
   */
  switchedNetwork(
    properties: SwitchedNetworkProperties,
    options?: EventOptions,
  ) {
    return this.track(new SwitchedNetwork(properties), options);
  }
}

export const ampli = new Ampli();

// BASE TYPES
type BrowserOptions = amplitude.Types.BrowserOptions;

export type BrowserClient = amplitude.Types.BrowserClient;
export type BaseEvent = amplitude.Types.BaseEvent;
export type IdentifyEvent = amplitude.Types.IdentifyEvent;
export type GroupEvent = amplitude.Types.GroupIdentifyEvent;
export type Event = amplitude.Types.Event;
export type EventOptions = amplitude.Types.EventOptions;
export type Result = amplitude.Types.Result;
