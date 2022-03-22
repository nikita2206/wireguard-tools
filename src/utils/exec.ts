export interface Options {
  /** Function to run when data is returned from exec */
  onData?: (data: string) => any
  /** Function to run when error occurs */
  onError?: (err: string) => any
  /** Function to run when exec ends */
  onClose?: (code: number) => any
}

export type execFunction = (command: string, opts?: Options) => Promise<string>
