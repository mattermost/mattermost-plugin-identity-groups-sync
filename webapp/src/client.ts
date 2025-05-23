// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import {Client4, ClientError} from '@mattermost/client';

import manifest from './manifest';

class APIClient {
    private readonly url = `/plugins/${manifest.id}/api/v1`;
    private readonly client4 = new Client4();

    getGroups = async (page: number, perPage: number, search?: string) => {
        const searchParam = search ? `&search=${encodeURIComponent(search)}` : '';
        return this.doGet(`${this.url}/groups?page=${page}&perPage=${perPage}${searchParam}`);
    };

    getGroupsCount = async (q?: string) => {
        const searchParam = q ? `?q=${encodeURIComponent(q)}` : '';
        return this.doGet(`${this.url}/groups/count${searchParam}`);
    };

    linkGroup = async (remoteId: string) => {
        return this.doWithBody(`${this.url}/groups/link`, 'post', {remote_id: remoteId});
    };

    unlinkGroup = async (remoteId: string) => {
        return this.doWithBody(`${this.url}/groups/unlink`, 'post', {remote_id: remoteId});
    };

    checkSyncJobRunning = async () => {
        return this.doGet(`${this.url}/jobs/sync`);
    };

    runSyncJob = async () => {
        return this.doWithBody(`${this.url}/jobs/sync`, 'post', {});
    };

    private doGet = async (url: string, headers = {}) => {
        const options = {
            method: 'get',
            headers,
        };

        const response = await fetch(url, this.client4.getOptions(options));

        if (response.ok) {
            return response.json();
        }

        const text = await response.text();

        throw new ClientError(this.client4.url, {
            message: text || '',
            status_code: response.status,
            url,
        });
    };

    private doWithBody = async (url: string, method: string, body: any, headers = {}) => {
        const options = {
            method,
            body: JSON.stringify(body),
            headers,
        };

        const response = await fetch(url, this.client4.getOptions(options));

        if (response.ok) {
            return response.json();
        }

        const text = await response.text();

        throw new ClientError(this.client4.url, {
            message: text || '',
            status_code: response.status,
            url,
        });
    };
}

const Client = new APIClient();
export default Client;
