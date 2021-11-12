import React from "react";
import Image from 'react-native';

import {
  ErrorBoundary,
  Facet,
  SearchProvider,
  WithSearch,
  SearchBox,
  Results,
  PagingInfo,
  ResultsPerPage,
  Paging,
  Sorting
} from "@elastic/react-search-ui";
import { Layout} from "@elastic/react-search-ui-views";
import "@elastic/react-search-ui-views/lib/styles/styles.css";
import "./styles/resultView.css";

import buildRequest from "./buildRequest";
import runRequest from "./runRequest";
import applyDisjunctiveFaceting from "./applyDisjunctiveFaceting";
import buildState from "./buildState";
import ResultView from "./ResultView";
import wazuhHeaderLogo from './data/wazuh_logo_w.png'

const config = {
  debug: true,
  alwaysSearchOnInitialLoad: true,
  hasA11yNotifications: true,

  onAutocomplete: async ({ searchTerm }) => {
    const requestBody = buildRequest({ searchTerm });
    const json = await runRequest(requestBody);
    const state = buildState(json);
    return {
      autocompletedResults: state.results
    };
  },
  onSearch: async state => {
    const { resultsPerPage } = state;
    const requestBody = buildRequest(state);
    // Note that this could be optimized by running all of these requests
    // at the same time. Kept simple here for clarity.
    const responseJson = await runRequest(requestBody);
    const responseJsonWithDisjunctiveFacetCounts = await applyDisjunctiveFaceting(
      responseJson,
      state,
      ["group_id", "tiers", "os_platform", "modules", "daemons", "components"]
    );
    return buildState(responseJsonWithDisjunctiveFacetCounts, resultsPerPage);
  },
};

export default function App() {
  return (
    <SearchProvider config={config}>
      <WithSearch 
      mapContextToProps={({ wasSearched }) => ({ wasSearched })}>
        {({ wasSearched }) => (
          <div className="App">
            <ErrorBoundary>
              <Layout
                header={
                  // <Image
                  // style={{ width: 30, height: 30, margin: 20 }}
                  // source={require(wazuhHeaderLogo)}
                  // />,
                  <SearchBox
                    autocompleteMinimumCharacters={3}
                    autocompleteResults={{
                      linkTarget: "_blank",
                      sectionTitle: "Results",
                      titleField: "name",
                      urlField: "",
                      shouldTrackClickThrough: true,
                      clickThroughTags: ["test"]
                    }}
                    autocompleteSuggestions={true}
                  />
                }
                sideContent={
                  <div>
                    {wasSearched && (
                      <Sorting
                        label={"Sort by"}
                        sortOptions={[
                          {
                            name: "Relevance",
                            value: "",
                            direction: ""
                          },
                          {
                            name: "Name",
                            value: "name",
                            direction: "asc"
                          }
                        ]}
                      />
                    )}
                    <Facet field="tier" label="tier:" filterType="any"/>
                    <Facet field="os_platform" label="os_platform:" filterType="any"/>
                    <Facet field="modules" label="modules:" filterType="any"/>
                    <Facet field="daemons" label="daemons:" filterType="any"/>
                    <Facet field="components" label="components:" filterType="any"/>
                  </div>
                }
                bodyContent={
                  <Results
                    label={"Name"}
                    titleField='name'
                    resultView={ResultView}
                    shouldTrackClickThrough={true}
                  />
                }
                bodyHeader={
                  <React.Fragment>
                    {wasSearched && <PagingInfo />}
                    {wasSearched && <ResultsPerPage />}
                  </React.Fragment>
                }
                bodyFooter={<Paging />}
              />
            </ErrorBoundary>
          </div>
        )}
      </WithSearch>
    </SearchProvider>
  );
}
